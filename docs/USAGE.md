# Usage

A walkthrough of every `llms` command. For *why* the tool is shaped this way, read the [README](../README.md) and the [ADRs](adr/).

## Install

```bash
cargo install llm-secrets
```

Or grab a pre-built binary from the [Releases](https://github.com/adjoint-uk/llm-secrets/releases) page.

## Initialise the store

```bash
llms init
```

Creates `~/.llm-secrets/` (mode 0700) containing:

- `identity.txt` — your age secret key. **Back this up.** Without it, the store is unrecoverable.
- `store.age` — the encrypted JSON store. Empty at first.

Override the location with `LLM_SECRETS_DIR=/path/to/dir`.

## Storing and inspecting secrets

```bash
# Interactive — hidden input, value never in shell history
llms set db_password

# Piped — useful for scripted setup or migrating from another tool
echo "hunter2" | llms set db_password --stdin

# List names (no values)
llms list

# Masked preview — shows you which secret you're looking at without
# leaking the value to your terminal scrollback
llms peek db_password
# → hunt**ter2

# Delete (asks for confirmation)
llms delete db_password
llms delete db_password --force
```

## Running a command with secrets injected

This is the **only** way plaintext leaves the binary, and it goes straight into a child process's environment — never your shell, never stdout, never an LLM context.

```bash
llms exec --inject DB_PASS=db_password -- psql -U admin mydb
llms exec \
    --inject DB_PASS=db_password \
    --inject API_KEY=stripe_key \
    -- ./run-tests.sh
```

`exec` exits with the child's exit code.

## Sessions and policy

A **session** is a signed, time-bounded statement of *who* is asking. Once you have a session, you can apply a policy to control which secrets are reachable.

```bash
# Start a session — gathers git config + repo + branch + agent + pid + ttl
llms session-start --ttl 1h

# Inspect (verifies the signature and the expiry)
llms session-info
```

To enforce a policy, drop a `.llm-secrets-policy.yaml` at the **git root** of the repo you're working in:

```yaml
secrets:
  db_password:
    allow:
      - repo: acme/billing
        branch: [main, develop]
        user: alice@acme.com
        agent: claude-code
        max_ttl: 10m
    deny:
      - branch: "*"  # everything else: denied
```

Match semantics:

- The policy is checked **on every read** (`peek`, `exec`, `lease`).
- Missing fields in a rule match anything.
- String fields can be a single value or a list (`branch: [main, develop]`).
- `"*"` is a wildcard.
- `deny` rules short-circuit `allow`.
- A key not mentioned in the policy is **denied** — explicit allow-list semantics.

If no `.llm-secrets-policy.yaml` exists, behaviour is **permissive** (backwards compatible with unmanaged use).

## Leases and audit

A **lease** records that a secret was granted to a session, with a TTL. It produces an audit trail.

```bash
# Grant a 5-minute lease (requires an active session)
llms lease db_password --ttl 5m

# See active leases
llms leases

# Inspect the audit log
llms audit
llms audit --last 50
llms audit --json
```

The audit log is at `$LLM_SECRETS_DIR/audit.jsonl`, append-only, mode 0600.

## Macaroons — delegating capability to an agent (v1.1+)

A **macaroon** is a bearer token the dev mints to grant an agent narrow, time-bounded access to specific secrets. The agent inherits *less* than the dev's session, never more — it cannot escalate by removing caveats. See [ADR 0006](adr/0006-macaroons.md) for the full design.

```bash
# Mint: scoped to one secret, 5 minutes, only for Claude Code on this branch
M=$(llms macaroon mint \
    --secret db_password \
    --ttl 5m \
    --agent claude-code \
    --branch main)

# Inspect — pure parse, never touches the store
echo "$M" | llms macaroon inspect

# Verify against the current session context
llms macaroon verify --macaroon "$M" --key db_password

# Hand to an agent via env var, then run it
export LLM_SECRETS_MACAROON="$M"
claude

# Or use it explicitly with one-shot exec
llms exec --inject DB=db_password --macaroon "$M" -- ./run-migrations.sh
```

The agent never sees the macaroon root key. It cannot mint new macaroons. It cannot widen the one it holds. Every use is audited (`peek.macaroon` / `exec.inject.macaroon`).

`revoke-all` deletes the root key, invalidating every derived macaroon in one shot.

> **v1.1 status:** the wire format is *experimental* — treat tokens as ephemeral. We may break the format in v1.2 if real-world usage exposes a problem.

## Killswitch

```bash
llms revoke-all
```

Deletes every active lease and the active session, and writes a `revoke.all` entry to the audit log. Use this when you suspect a session has been compromised. (`--rotate`, which also re-encrypts the store under a new age key, is planned for v1.x.)

## MCP server

`llms mcp` runs a Model Context Protocol server on stdio for AI agents. The exposed tool surface is **deliberately a subset** of the CLI:

| MCP tool | What it does |
|---|---|
| `list_secrets` | Returns key names. |
| `peek_secret` | Returns the **masked** preview. |
| `audit_recent` | Read-only inspection of the audit log. |
| `status` | Store health. |

There is no MCP tool that returns plaintext, by design. See [ADR 0005](adr/0005-mcp-server.md).

To wire it into Claude Code, add to your MCP config:

```json
{
  "mcpServers": {
    "llm-secrets": {
      "command": "llms",
      "args": ["mcp"]
    }
  }
}
```

## Status and troubleshooting

```bash
llms status
```

Reports the store directory, whether `identity.txt` and `store.age` are present, and the secret count.

If `cargo install llm-secrets` fails, check that your Rust toolchain is at least 1.75 (we use edition 2024 features).
