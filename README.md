# llm-secrets

Workload identity for AI agents — prove who you are, access only what you should, for only as long as you need.

## The Problem

AI coding agents (Claude Code, Cursor, Copilot) run with your full identity. They can read `.env` files, environment variables, and anything in your filesystem. There's no boundary between what the agent needs and what it can see.

Existing tools either:
- **Output raw secrets** that get captured in LLM context (`.env`, `sops`, `doppler run`)
- **Use proxy daemons** that add operational complexity (agentsecrets, agent-secrets)
- **Rely on honour systems** — telling the agent "don't look" isn't security

## The Approach

`llm-secrets` applies the **workload identity** pattern — the same model used by AWS IAM Roles Anywhere, SPIFFE, and HashiCorp Vault WIF — to AI coding agents.

The agent doesn't manage secrets. It **proves what it is**, and a policy engine decides what it can access:

```
Agent starts session → attestation signed:
  who:   cptfinch (from git config)
  where: adjoint-uk/billing, branch main
  what:  Claude Code, pid 12345
  when:  2026-03-22T11:00:00Z

Agent requests secret → policy evaluated:
  db_password → allowed (repo match, user match, TTL 5m)
  stripe_key  → denied  (wrong repo)
```

**There is no `get` command.** This is architectural enforcement, not a convention.

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

```bash
# Initialise (generates age keypair)
llms init

# Store a secret (hidden input)
llms set db_password

# List keys (no values)
llms list

# Masked preview
llms peek db_password
# → db_pa****word

# Run a command with secrets injected
llms exec --inject DB_PASS=db_password -- psql -U admin mydb

# Check status
llms status
```

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

## Roadmap

See [milestones](https://github.com/adjoint-uk/llm-secrets/milestones) for the full plan:

- **v0.2** — Age encryption, no SOPS dependency, Rust rewrite
- **v0.3** — Session identity, attestation, policy engine
- **v0.4** — Leases, audit log, killswitch
- **v1.0** — MCP server, CI/CD, docs, crates.io release

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

MIT — see [LICENSE](LICENSE).
