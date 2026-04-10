# Usage

`llm-secrets` has two use cases. They share the same store and the same
commands, but the *reason* you're using the tool is different, and that
changes which commands matter.

1. **You, in your terminal** — running commands that need secrets
   (`psql`, deploy scripts, API calls). `llms` keeps secrets out of
   `.env` files, shell history, and terminal scrollback.

2. **Delegating to an AI agent** — handing a narrow, time-bounded,
   revocable slice of your identity to Claude Code / Cursor / Copilot.
   The agent gets only what it needs, only for as long as it needs it,
   and you can kill the grant instantly.

For *why* the tool is shaped this way, read the [README](../README.md)
and the [ADRs](adr/).

## Install

```bash
cargo install llm-secrets
```

Or grab a pre-built binary from the
[Releases](https://github.com/adjoint-uk/llm-secrets/releases) page.

## Setup (one-time)

```bash
llms init
```

Creates `~/.llm-secrets/` containing:

- `identity.txt` — your age secret key. **Back this up.** Lose it, lose the store.
- `store.age` — the encrypted JSON store.

Override the location with `LLM_SECRETS_DIR=/path/to/dir`.

```bash
# Add secrets (hidden input — never in shell history)
llms set db_password

# Or pipe from another tool / migration script
echo "$DB_PASSWORD" | llms set db_password --stdin

# See what you have
llms list

# Masked preview (never the full value)
llms peek db_password
# → hunt****ter2
```

---

## Use Case 1: You, in your terminal

This is daily driving. You need secrets injected into a child process.
No sessions, no macaroons, no ceremony — just `exec`.

### One-off commands

```bash
# Inject one secret
llms exec --inject DB_PASS=db_password -- psql -U admin mydb

# Inject several
llms exec \
    --inject DB_PASS=db_password \
    --inject API_KEY=stripe_key \
    -- ./run-tests.sh
```

The plaintext goes into the child process's environment, never your
shell, never stdout, never an LLM context. `exec` exits with the
child's exit code.

### Profiles — the repeatable way

When you find yourself typing the same `--inject` flags every day,
define a profile in `~/.config/llm-secrets/profiles.toml`:

```toml
[mydb]
secrets = ["db_password"]
ttl     = "1h"

[mydb.env]
DB_PASS = "db_password"

[deploy]
secrets = ["db_password", "api_key"]
ttl     = "30m"

[deploy.env]
DB_PASS = "db_password"
API_KEY = "api_key"
```

Then:

```bash
llms profile list                                    # what's defined?
llms profile show deploy                             # secrets, env map, caveats
llms profile exec mydb -- psql -U admin mydb         # one command
llms profile exec deploy -- ./deploy.sh              # multiple secrets
llms exec --profile deploy -- ./deploy.sh            # alias, same thing
```

Profiles are config (TOML, editable, dotfile-managed). Stealing one
gets you a list of secret *names*, not values. Under the hood, `profile
exec` mints a short-lived macaroon and uses it for the `exec` — but you
never need to think about that.

### That's it

For use case 1, the commands you'll type are:

| Command | When |
|---|---|
| `llms set <key>` | Adding a secret |
| `llms profile exec <name> -- <cmd>` | **Daily use** |
| `llms peek <key>` | "Did I store the right thing?" |
| `llms list` | "What secrets do I have?" |
| `llms delete <key>` | Removing a secret |

No `session-start` needed. Sessions are auto-created on first read.

---

## Use Case 2: Delegating to an AI agent

This is the headline. When an AI agent runs on your machine, it
inherits your full identity — your `.env` files, your `~/.aws/credentials`,
everything. `llms` lets you delegate a *narrow slice* instead.

The primitive is a **macaroon**: a signed, time-bounded bearer token
with caveats (secret, repo, branch, agent, TTL) enforced by an
HMAC-SHA256 chain. The agent can use what you've given it. It cannot
widen the grant. It cannot escalate.

### Step 1: Start a session

For delegation, you start a session explicitly. This is the conscious
"I am delegating to an agent now" gesture.

```bash
llms session-start --ttl 8h       # workday-length session
llms session-info                  # verify what's active
```

### Step 2: Mint a token

**By hand (full control over every caveat):**

```bash
M=$(llms macaroon mint \
    --secret db_password \
    --ttl 5m \
    --branch main \
    --agent claude-code)
```

**Via profile (same thing, less typing):**

```bash
eval "$(llms profile mint deploy --ttl 5m)"
# LLM_SECRETS_MACAROON is now in the shell environment
```

Both produce the same shaped macaroon. Profiles just save you retyping
the caveat list.

### Step 3: Hand it to the agent

```bash
# Via env var (the standard way)
LLM_SECRETS_MACAROON=$M claude

# Or one-shot exec
LLM_SECRETS_MACAROON=$M llms exec --inject DB=db_password -- ./migrate.sh

# Or via profile exec (mints + execs in one step)
llms profile exec deploy -- ./deploy.sh
```

### Step 4: What the agent CAN'T do

The token is cryptographically narrowed. The agent cannot:

- **Read a secret not in the token** — `peek api_key` fails if the token only covers `db_password`.
- **Extend the TTL** — removing or modifying the `expires_at` caveat invalidates the HMAC chain.
- **Switch branches/repos** — `branch_eq` and `repo_eq` caveats are baked in.
- **Mint its own tokens** — it doesn't have the root key.
- **See plaintext on stdout** — there is no `get` command, not even an MCP tool that returns plaintext.

### Step 5: Inspect and verify

```bash
# What does this token allow? (pure parse, never touches the store)
llms macaroon inspect --macaroon "$M"

# Is it valid right now, in this context?
llms macaroon verify --macaroon "$M" --key db_password
```

### Step 6: Killswitch

```bash
llms revoke-all              # delete root key → every token dead in O(1)
llms revoke-all --rotate     # also re-encrypt the store under a fresh age key
```

Your secrets are untouched. Only the macaroon chain dies. Start a new
session and you're back in business.

### The commands you'll type

| Command | When |
|---|---|
| `llms session-start --ttl 8h` | Before a delegation session |
| `llms macaroon mint ...` | One-off, ad-hoc delegation |
| `eval "$(llms profile mint <name>)"` | Repeated delegation pattern |
| `llms profile exec <name> -- <cmd>` | Mint + exec in one step |
| `llms macaroon inspect --macaroon $M` | Debugging token issues |
| `llms audit --last 20` | "What did the agent touch?" |
| `llms revoke-all` | Something looks wrong |

---

## Policy file (optional)

Drop `.llm-secrets-policy.yaml` at the git root of a repo to control
which secrets are reachable by identity:

```yaml
secrets:
  db_password:
    allow:
      - repo: acme/billing
        branch: [main, develop]
        user: alice@acme.com
        agent: claude-code
    deny:
      - branch: "*"
```

- Checked on **every read** (`peek`, `exec`, `lease`).
- Missing fields match anything. `"*"` is a wildcard.
- `deny` rules short-circuit `allow`.
- Unmentioned keys are **denied** (explicit allow-list).
- No policy file = permissive (backwards compatible).

## Leases and audit

```bash
llms lease db_password --ttl 5m     # time-bounded access grant
llms leases                          # active leases
llms audit                           # who/when/what for every read
llms audit --last 50 --json          # raw JSONL
```

Audit log: `$LLM_SECRETS_DIR/audit.jsonl`, append-only, mode 0600.

## MCP server

`llms mcp` runs a Model Context Protocol server on stdio. The tool
surface is deliberately a subset — **no MCP tool returns plaintext**:

| MCP tool | Description |
|---|---|
| `list_secrets` | Key names |
| `peek_secret` | Masked preview |
| `audit_recent` | Audit log entries |
| `status` | Store health |

Wire into Claude Code:

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

See [ADR 0005](adr/0005-mcp-server.md).

## Status and troubleshooting

```bash
llms status        # store directory, identity, secret count
llms --version     # confirm installed version
```

If `cargo install` fails, ensure Rust >= 1.85 (edition 2024).
