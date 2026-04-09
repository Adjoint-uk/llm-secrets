# llm-secrets

[![CI](https://github.com/adjoint-uk/llm-secrets/actions/workflows/ci.yml/badge.svg)](https://github.com/adjoint-uk/llm-secrets/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**The first secrets manager built around capability delegation for AI coding agents.**

You don't *give* your AI agent your credentials. You *delegate* a slice of your identity to it — narrowed to one secret, one repo, one branch, five minutes — using an attenuated, signed bearer token. The agent can use what you've given it. It cannot widen the grant. It cannot escalate.

## The Problem

AI coding agents (Claude Code, Cursor, Copilot, Aider) run with your full identity. They can read your `.env` files, your shell history, your `~/.aws/credentials`, anything on your filesystem. The secrets managers you already use weren't built for this — they all have a `get` command that prints plaintext to stdout, which in an LLM context is a leak that gets persisted to transcripts, training data, and provider logs. Telling the agent *"please don't"* is a request, not security.

The existing answers in this niche all miss the point:

- **`.env` files, `sops`, `doppler run`** — output raw secrets to stdout. Game over the moment an agent reads them.
- **Proxy daemons (`agentsecrets`, `agent-secrets`)** — sit between the agent and the secret store and try to filter. Behavioural patches on a structural problem.
- **Honour systems** — *"agent, please don't look at the .env"*. Not security.

## The Approach — capability delegation

`llm-secrets` borrows from a pattern that took cloud computing from "VM with a password" to "workload identity with IAM": **the requester carries no secret material, only a narrowed grant of authority.**

The dev mints a **macaroon** — a signed bearer token — scoped to exactly what the agent needs to do this one task:

```bash
# Mint: scoped to one secret, 5 minutes, only on this branch, only for Claude Code
M=$(llms macaroon mint \
    --secret db_password \
    --ttl 5m \
    --branch main \
    --agent claude-code)

# Hand it to the agent — it inherits a slice of your identity, not all of it
LLM_SECRETS_MACAROON=$M claude
```

The agent now holds a token that is *cryptographically* incapable of being widened. Every caveat (`secret`, `branch`, `agent`, `expires_at`, …) is enforced by an HMAC-SHA256 chain. Removing or substituting a caveat invalidates the signature. The agent can do *less* than you can, never more — and revocation is one command (`llms revoke-all` deletes the per-session HMAC root key, invalidating every derived macaroon in O(1)).

This is the same pattern Tailscale and Fly.io use for service auth — applied, for the first time, to AI coding agents.

## What this is built on

Underneath the macaroon layer, `llm-secrets` is also a properly-built workload-identity tool:

- **Encrypted store** at rest using `age` (X25519 + ChaCha20-Poly1305).
- **Signed sessions** — every operation is anchored to a tamper-evident, time-bounded claim of *who/where/what/when*, with the agent type auto-detected from the environment (Claude Code, Cursor, Copilot, Aider, Continue, Windsurf).
- **Allow-list policy file** — drop a `.llm-secrets-policy.yaml` at the repo root; unmentioned keys are denied; deny rules short-circuit allows.
- **Append-only audit log** — every secret access recorded with the full claim set.
- **MCP server mode** — `llms mcp` exposes a *strict subset* of the CLI to MCP-compatible AI agents. **There is no MCP tool that returns plaintext.** The model literally cannot ask for one.
- **No `get` command.** Plaintext leaves the binary only via `exec --inject` (into a child process's environment) or `peek` (deliberately lossy mask). This is *architectural enforcement* — verifiable in 50 lines of source — not a convention.

The macaroon layer is the cutting edge. Everything else is the foundation that makes the cutting edge mean something.

## Installation

```bash
cargo install llm-secrets
```

Or build from source:

```bash
git clone https://github.com/adjoint-uk/llm-secrets.git
cd llm-secrets
cargo build --release
```

## Quick Start

### One-time setup

```bash
cargo install llm-secrets

llms init                                    # generates an age identity, creates the encrypted store
llms session-start --ttl 8h                  # mints your root macaroon
echo "$DB_PASSWORD" | llms set db_password --stdin
```

### The easy way — profiles (v2.1+)

A **profile** is a TOML recipe that groups secrets and env-var mappings under a name. Edit once, use everywhere. The profile is config; the macaroon it produces at use time is still the unforgeable, time-bounded token.

```bash
mkdir -p ~/.config/llm-secrets
cat > ~/.config/llm-secrets/profiles.toml <<'EOF'
[db]
secrets = ["db_password"]
ttl     = "5m"

[db.env]
DB_PASS = "db_password"
EOF
```

Then:

```bash
# You, directly:
llms profile exec db -- psql -U admin mydb

# Or hand a minted token to an agent:
eval "$(llms profile mint db)"
claude            # inherits LLM_SECRETS_MACAROON, narrowed to db_password for 5 minutes
```

Editing the profile is free — no re-minting, no token redistribution. The TOML is non-secret config: stealing it gets you a list of names, no access. The macaroon is the only thing carrying authority, and it's always short-lived and context-restricted.

### The manual way — direct CLI / macaroon mint

For one-off scripts or when you don't want a profile:

```bash
# Direct CLI (you, in your own terminal):
llms exec --inject DB_PASS=db_password -- psql -U admin mydb

# Mint a macaroon by hand and hand it to an agent:
M=$(llms macaroon mint \
    --secret db_password \
    --ttl 5m \
    --branch main \
    --agent claude-code)
LLM_SECRETS_MACAROON=$M claude
```

The agent can use `db_password` via `llms exec` for the next 5 minutes, only on this branch, only as `claude-code`. It cannot read any other secret. It cannot extend the TTL. It cannot remove the caveats. Every access is recorded in the audit log.

When you're done — or if anything looks wrong — `llms revoke-all` deletes the macaroon root key and invalidates every derived token in O(1). `llms revoke-all --rotate` additionally re-encrypts the on-disk store under a fresh age key.

## Commands

### Core (v0.2)

| Command | Description | LLM Safe |
|---------|-------------|----------|
| `llms init` | Initialise secrets store with age encryption | Yes |
| `llms list` | List secret keys (names only) | Yes |
| `llms peek <key>` | Masked preview of a value | Yes |
| `llms set <key>` | Store secret via hidden input | Yes |
| `llms delete <key>` | Remove a secret | Yes |
| `llms exec --inject VAR=key -- cmd` | Run command with secrets injected | Yes |
| `llms status` | Check store and dependencies | Yes |

### Agent Identity (v0.3)

| Command | Description |
|---------|-------------|
| `llms session-start` | Start authenticated session with attestation |
| `llms session-info` | Show current session identity |

### Temporal Enforcement (v0.4)

| Command | Description |
|---------|-------------|
| `llms lease <key> --ttl 5m` | Request time-bounded secret access |
| `llms leases` | List active leases |
| `llms audit` | View access audit log |
| `llms revoke-all [--rotate]` | Emergency killswitch (`--rotate` re-encrypts the store) |

### Capability delegation — macaroons (v2.0)

| Command | Description |
|---------|-------------|
| `llms macaroon mint --secret <k> --ttl <t> [--branch <b> --agent <a>]` | Mint a delegated bearer token |
| `llms macaroon inspect [--macaroon <m>]` | Pretty-print a macaroon (pure parse) |
| `llms macaroon verify [--macaroon <m>] [--key <k>]` | Verify signature + caveats against current context |

### Profiles — the recipe layer (v2.1)

| Command | Description |
|---------|-------------|
| `llms profile list` | List profiles in `~/.config/llm-secrets/profiles.toml` |
| `llms profile show <name>` | Show secrets, env mapping, ttl, caveats |
| `llms profile mint <name> [--ttl <t>]` | Mint a macaroon and print `export LLM_SECRETS_MACAROON=…` |
| `llms profile exec <name> [--ttl <t>] -- <cmd>` | Mint + exec with the profile's env vars injected |
| `llms exec --profile <name> -- <cmd>` | Alias for `profile exec` |

## Policy File

Create `.llm-secrets-policy.yaml` in your repo to control access by identity:

```yaml
secrets:
  db_password:
    allow:
      - repo: adjoint-uk/billing
        branch: [main, develop]
        user: cptfinch
        max_ttl: 10m
    deny:
      - branch: "*"  # deny by default

  stripe_key:
    allow:
      - repo: adjoint-uk/billing
        user: cptfinch
        max_ttl: 5m
```

Without a policy file, all secrets are accessible (backwards compatible).

## How It Compares

| | llm-secrets | agentsecrets | agent-secrets | sops / doppler |
|---|---|---|---|---|
| **Enforcement** | Architectural (no get command) | Proxy intercept | Lease expiry | None |
| **Identity model** | Workload attestation | None | None | None |
| **Policy** | Declarative YAML | Domain allowlist | None | IAM policies |
| **Access model** | Time-bounded leases | Persistent proxy | Session leases | Static |
| **Language** | Rust | Go | Go | Go |
| **Dependencies** | Single binary | Go + OS keychain | Go + age | Multiple |

## Security Model

- **Encryption at rest**: age (X25519 + ChaCha20-Poly1305)
- **Session identity**: Ed25519 ephemeral keypairs with attestation
- **No raw output**: secrets only enter subprocess environments, never stdout
- **Temporal bounds**: leases expire, killswitch revokes all
- **Audit trail**: append-only JSONL log of every access

## Documentation

- [Usage walkthrough](docs/USAGE.md) — every command with examples
- [Security model](docs/SECURITY-MODEL.md) — threat model + architectural guarantees
- [ADRs](docs/adr/) — design decisions, including why there is no `get` command

## Status

**v2.1 — released.** Adds **TOML profiles** — named recipes that group secrets and env-var mappings — so consuming many secrets from many tools no longer needs wrapper-script boilerplate. Profiles are config; the macaroons they produce at use time are still the unforgeable, time-bounded tokens. See [ADR 0008](docs/adr/0008-toml-profiles.md) for the design and [CHANGELOG](CHANGELOG.md) for the full notes.

Built on **v2.0**, the macaroon merge: the session and the delegated token are the **same primitive** — both are macaroons. Reads always travel through a verified token. See [ADR 0007](docs/adr/0007-macaroon-merge.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

MIT — see [LICENSE](LICENSE).
