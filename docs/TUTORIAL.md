# Tutorial

`llms` is a secret manager for AI coding agents. Two use cases:

1. You need secrets in a command (psql, deploy, curl)
2. You need to hand secrets to an AI agent safely

## Setup (once)

```bash
cargo install llm-secrets
llms init
```

This creates `~/.local/share/llm-secrets/` with an age-encrypted store
and an identity key. **Back up `identity.txt`** — lose it, lose the store.

Add some secrets:

```bash
llms set db_password                # hidden input, never in shell history
llms set api_key --stdin < key.txt  # or piped
llms list                           # see what you have
llms peek db_password               # masked preview, never the full value
```

## Use case 1: You, running commands that need secrets

You need `db_password` injected into `psql`. One command:

```bash
llms exec --inject DB_PASS=db_password -- psql -U admin mydb
```

The secret goes into the child process's environment, never your shell,
never stdout. When the child exits, the secret is gone.

### Profiles — the repeatable way

When you type the same `--inject` flags daily, define a profile once:

```toml
# ~/.config/llm-secrets/profiles.toml
[db]
secrets = ["db_password"]
ttl     = "1h"

[db.env]
DB_PASS = "db_password"
```

Then:

```bash
llms profile exec db -- psql -U admin mydb
```

That's it. No session-start, no tokens, no ceremony.

### Use case 1 cheat sheet

```
llms set <key>                          add a secret
llms list                               list secret names
llms peek <key>                         masked preview
llms exec --inject VAR=key -- <cmd>     one-off injection
llms profile exec <name> -- <cmd>       daily use with profiles
```

---

## Use case 2: Handing secrets to an AI agent

The difference: you are giving an **untrusted** process a narrow,
time-bounded, revocable slice of your identity.

### What is a macaroon?

A macaroon is a **signed permission slip**, not a secret. It says:

> *"This bearer may access `db_password`, for 5 minutes, on branch
> `main`, as agent `claude-code`."*

It does not contain the secret value. It's a proof of authorization
that gates whether a request is allowed. The actual secret is decrypted
and injected only when the agent asks for it via `llms exec` and every
caveat on the macaroon passes.

Each caveat (secret, TTL, branch, agent, repo, user) is enforced by an
HMAC-SHA256 chain. Removing or changing any caveat breaks the chain.
The agent cannot widen the grant — only narrow it further.

### Step by step

**Mint a token:**

```bash
M=$(llms macaroon mint --secret db_password --ttl 5m)
```

**See what's in it:**

```bash
llms macaroon inspect --macaroon "$M"
# → caveats: secret == db_password, expires in 5m, branch == main, agent == claude-code
```

**Hand it to the agent:**

```bash
LLM_SECRETS_MACAROON=$M claude
```

**What happens when the agent uses it:**

```
Agent runs:   llms exec --inject DB=db_password -- psql
llms checks:  is the HMAC chain valid?                    → yes
              does secret_eq allow "db_password"?          → yes
              is expires_at still in the future?           → yes
              does branch_eq match the current branch?     → yes
              does agent_eq match the detected agent?      → yes
              → ALL PASS → decrypt → inject into child env → psql runs
```

**What happens when the agent tries something it wasn't given:**

```
Agent runs:   llms peek api_key
llms checks:  does secret_eq allow "api_key"?              → NO
              → DENIED
```

**What did it touch?**

```bash
llms audit --last 10
```

**Kill everything — every minted token dies instantly:**

```bash
llms revoke-all
```

The root HMAC key is deleted. Every macaroon derived from that session
becomes unverifiable in O(1). Your secrets are untouched — only the
authorization chain dies. Start a new session and you're back.

### Profiles work here too

Instead of typing caveats by hand every time:

```bash
eval "$(llms profile mint db --ttl 5m)"    # mint into shell env
claude                                      # agent inherits the token
```

Or mint and exec in one step:

```bash
llms profile exec db -- ./deploy.sh
```

The macaroon under the hood is the same shape whether you mint by hand
or via profile. Profiles just save you retyping the caveat list.

### Use case 2 cheat sheet

```
llms macaroon mint --secret <k> --ttl <t>   mint a delegation token
llms macaroon inspect --macaroon $M         what does this token allow?
eval "$(llms profile mint <name>)"          mint via profile
llms audit --last 20                        what did the agent touch?
llms revoke-all                             kill all tokens instantly
```

---

## All commands

| Command | What it does |
|---|---|
| `llms init` | Create the encrypted store (once) |
| `llms set <key>` | Add a secret |
| `llms list` | List secret names |
| `llms peek <key>` | Masked preview |
| `llms delete <key>` | Remove a secret |
| `llms exec --inject VAR=key -- <cmd>` | Inject + run (one-off) |
| `llms profile list` | List defined profiles |
| `llms profile show <name>` | Show a profile's details |
| `llms profile exec <name> -- <cmd>` | Inject via profile + run |
| `llms macaroon mint --secret <k> --ttl <t>` | Mint a delegation token |
| `llms macaroon inspect --macaroon $M` | Inspect a token |
| `llms macaroon verify --macaroon $M` | Verify a token is valid now |
| `llms audit` | Access log |
| `llms revoke-all` | Kill all tokens + session |
| `llms revoke-all --rotate` | Kill + re-encrypt the store |
| `llms session-start --ttl 8h` | Optional: explicit longer session |
| `llms status` | Store health check |
