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

### Set up the store (one-time)

```bash
llms init                                    # generates an age identity, creates the encrypted store
echo "$DB_PASSWORD" | llms set db_password --stdin
```

### Direct CLI use (you, in your own terminal)

```bash
llms exec --inject DB_PASS=db_password -- psql -U admin mydb
```

### Agent use — the recommended pattern (you handing work to an AI agent)

```bash
# Start a session (signed claim of who/where/what/when)
llms session-start --ttl 1h

# Mint a macaroon scoped to exactly this task
M=$(llms macaroon mint \
    --secret db_password \
    --ttl 5m \
    --branch main \
    --agent claude-code)

# Hand it to the agent. The agent inherits the capability — not your full identity.
LLM_SECRETS_MACAROON=$M claude
```

The agent can use `db_password` via `llms exec` for the next 5 minutes, only on this branch, only as `claude-code`. It cannot read any other secret. It cannot extend the TTL. It cannot remove the caveats. Every access is recorded in the audit log.

When you're done — or if anything looks wrong — `llms revoke-all` deletes the macaroon root key and invalidates every derived token in O(1).

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
| `llms revoke-all` | Emergency killswitch |

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

**v2.0 — released.** The session and the delegated token are **the same primitive** — both are macaroons. There is no other identity object in the system. Reads always travel through a verified token (the dev's root, loaded automatically, or an explicit child handed to an agent). Killswitch is one command. See [ADR 0007](docs/adr/0007-macaroon-merge.md) for the v2.0 design and [CHANGELOG](CHANGELOG.md) for the migration note.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

MIT — see [LICENSE](LICENSE).
