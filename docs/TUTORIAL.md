# Tutorial

`llms` is a secret manager for AI coding agents. Two use cases:

1. You need secrets in a command (psql, deploy, curl)
2. You need to hand secrets to an AI agent safely

## Setup (once)

```bash
cargo install llm-secrets
llms init
llms set db_password                # hidden input
llms set api_key --stdin < key.txt  # or piped

llms list                           # see what you have
llms peek db_password               # masked preview
```

## Use case 1: You, running commands that need secrets

```bash
# One-off:
llms exec --inject DB=db_password -- psql -U admin mydb
```

Repeatable — define a profile once:

```bash
cat > ~/.config/llm-secrets/profiles.toml <<'EOF'
[db]
secrets = ["db_password"]
ttl     = "1h"

[db.env]
DB_PASS = "db_password"
EOF
```

Then just:

```bash
llms profile exec db -- psql -U admin mydb
```

That's it. No session-start, no tokens, no ceremony.
The secret goes into the child process env, never stdout.

## Use case 2: Handing secrets to an AI agent

The difference: you are giving an untrusted process a **narrow,
time-bounded, revocable** slice of your identity.

```bash
# Mint a token — the agent gets db_password for 5 minutes
M=$(llms macaroon mint --secret db_password --ttl 5m)

# Hand it to the agent
LLM_SECRETS_MACAROON=$M claude
```

What can the agent do?

- `llms exec --inject DB=db_password -- psql` — **works**
- `llms peek api_key` — **DENIED** (wrong secret)
- Remove the 5m expiry — **DENIED** (breaks the HMAC chain)

What did it touch?

```bash
llms audit --last 10
```

Kill everything — every minted token dies instantly:

```bash
llms revoke-all
```

## Cheat sheet

| Command | What it does |
|---|---|
| `llms set <key>` | Add a secret |
| `llms list` | List secret names |
| `llms peek <key>` | Masked preview |
| `llms profile exec <name> -- <cmd>` | Daily use |
| `llms macaroon mint --secret <k> --ttl <t>` | Delegate to agent |
| `llms audit` | What was accessed |
| `llms revoke-all` | Kill all tokens |
