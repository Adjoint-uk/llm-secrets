# ADR 0008 — TOML profile definitions (the recipe layer)

- **Status**: Accepted (shipped in v2.1.0, 2026-04-09)
- **Date**: 2026-04-09
- **Builds on**: ADR 0006 (macaroons), ADR 0007 (one-primitive macaroon model)
- **Internal design notes**: `docs/internal/v2.1-mint-macaroon-profiles.md`
- **Implemented in**: `src/profile.rs`, `src/cli.rs` (`Profile` subcommand), `tests/cli.rs` (profile_*)

## Context

After v2.0 shipped (one-primitive macaroon model), the first real-world consumer to break was a custom CLI (`iba-connect`) that had been hardcoded against the v1 `llms get` command. The v2-idiomatic fix was to wrap the consumer in `llms exec -i ENV=key -- cmd`, but for any tool that needs more than two or three secrets, the wrapper-script boilerplate gets repetitive fast:

```bash
exec llms exec \
  -i IBA_AD_USERNAME=iba_ad_username \
  -i IBA_AD_PASSWORD=iba_ad_password \
  -i IBA_JIRA_TOKEN=iba_jira_api_key \
  -i IBA_CONFLUENCE_TOKEN=iba_confluence_token \
  -- "$@"
```

Multiply this across iba-connect, iba-jira, iba-confluence, adjoint deploy scripts, etc., and we have the same `-i` block copy-pasted into every wrapper. There is no shared notion of "the iba secrets" or "the adjoint secrets" — that grouping exists only in the user's head and gets re-encoded into every consumer.

### What we considered and rejected

**Macaroon-only profiles.** First instinct was to make a "named macaroon" the profile: `llms macaroon mint --name iba ...` writes to `~/.llm-secrets/profiles/iba.macaroon`, and `llms exec --profile iba` loads it. This conflates two distinct things — the *recipe* (which secrets are in the iba bundle, how they map to env vars) and the *capability* (an unforgeable, time-bounded bearer token). It forces re-minting on every recipe change, embeds long-lived configuration into short-lived tokens, and means the `EnvMap` would have to live inside the macaroon as a new caveat type — increasing crypto-layer surface area for what is fundamentally a config-layer problem.

**One macaroon caveat per env mapping.** Same problem at finer grain. Cryptographic primitives should not be where users edit their workflow.

## Decision

There are **two layers**:

| Layer | Lifetime | Editable? | Format | Where |
|---|---|---|---|---|
| **Profile definition** (the recipe) | Forever | Yes | TOML | `$XDG_CONFIG_HOME/llm-secrets/profiles.toml` |
| **Profile instance** (the capability) | Minutes to hours | No | Macaroon (existing) | Returned by `llms profile mint`, never written to disk by default |

The TOML is read by the CLI at command time, used to derive a fresh set of caveats, and passed to the existing mint logic. The macaroon format on disk does not change. The `Caveat` enum does not change. v2.1 is purely additive.

```
profiles.toml  ──(read at mint time)──▶  llms profile mint iba  ──▶  bearer macaroon
   (config layer)                              (action)                (capability layer)
```

### Rationale

1. **Editing a profile doesn't require re-minting.** Users edit toml; next mint picks up changes. With macaroon-only profiles, every edit forces re-mint and re-distribution.
2. **A stolen `profiles.toml` confers no authority.** It's just a recipe. An active session is still required to mint from it. By contrast, a stolen macaroon file *is* bearer authority — but it's time-bounded and context-restricted, and the toml is the part most likely to be synced via dotfiles.
3. **Long-lived editable thing = config. Short-lived unforgeable thing = token.** That is the right split. Mixing them is a smell.
4. **Maps onto the way users think.** Users say "the iba secrets." That's a category, not a token. Categories belong in config files; tokens are the runtime artifacts derived from them.
5. **Zero changes to crypto-layer code.** The macaroon serialisation, the caveat enum, the verification path, the audit log — all unchanged. v2.1 is one new module (`src/profile.rs`) plus three CLI commands.

## Schema

```toml
# ~/.config/llm-secrets/profiles.toml

[iba]
secrets = [
  "iba_ad_username",
  "iba_ad_password",
  "iba_jira_api_key",
  "iba_confluence_token",
]
ttl = "8h"             # default ttl when minting; --ttl on CLI overrides

[iba.env]
IBA_AD_USERNAME      = "iba_ad_username"
IBA_AD_PASSWORD      = "iba_ad_password"
IBA_JIRA_TOKEN       = "iba_jira_api_key"
IBA_CONFLUENCE_TOKEN = "iba_confluence_token"

[adjoint]
secrets = [
  "cloudflare_api_token",
  "hetzner_api_key",
  "supabase_access_token",
  "github_token",
]
ttl   = "1h"
agent = "claude-code"   # optional: only valid when called from this agent
repo  = "adjoint/*"     # optional: only valid in matching repo (Phase 2: glob support)

[adjoint.env]
CLOUDFLARE_API_TOKEN = "cloudflare_api_token"
HETZNER_TOKEN        = "hetzner_api_key"
SUPABASE_TOKEN       = "supabase_access_token"
GITHUB_TOKEN         = "github_token"
```

### Rust shape

```rust
// src/profile.rs
pub struct Profile {
    pub name: String,
    pub secrets: Vec<String>,
    pub env: BTreeMap<String, String>,  // ENV_VAR -> secret_key
    pub ttl: chrono::Duration,
    pub repo: Option<String>,
    pub branch: Option<String>,
    pub agent: Option<String>,
}

impl Profile {
    pub fn load(name: &str) -> Result<Self>;
    pub fn list() -> Result<Vec<Profile>>;
    pub fn to_caveats(&self, ttl_override: Option<Duration>) -> Vec<Caveat>;
    pub fn validate(&self) -> Result<()>;  // conflict detection (see below)
}
```

`to_caveats` produces:
- `Caveat::SecretsIn(self.secrets.clone())`
- `Caveat::ExpiresAt(now + ttl_override.unwrap_or(self.ttl))`
- `Caveat::RepoEq(repo)` if `self.repo.is_some()` (Phase 1: exact match only; glob is Phase 2)
- `Caveat::BranchEq(branch)` if `self.branch.is_some()`
- `Caveat::AgentEq(agent)` if `self.agent.is_some()`

The `env` map is **not** turned into caveats. It is metadata used by the CLI's `exec --profile` path to drive `-i` injections. This is the clean-layering payoff: env mapping is config, not crypto.

## CLI surface

```bash
llms profile list                    # no session required (config-only operation)
llms profile show <name>             # no session required (config-only operation)
llms profile mint <name> [--ttl 1h]  # session required; prints `export LLM_SECRETS_MACAROON=...`
llms profile exec <name> -- <cmd>    # session required; mints + execs in one step

# Equivalent: --profile flag on existing exec
llms exec --profile <name> -- <cmd>  # alias for `profile exec`
```

`profile show iba` prints:
```
profile:  iba
secrets:  iba_ad_username, iba_ad_password, iba_jira_api_key, iba_confluence_token
env:
  IBA_AD_USERNAME      <- iba_ad_username
  IBA_AD_PASSWORD      <- iba_ad_password
  IBA_JIRA_TOKEN       <- iba_jira_api_key
  IBA_CONFLUENCE_TOKEN <- iba_confluence_token
ttl:      8h
caveats:  (none beyond secrets+ttl)
```

## Decisions on the open questions

These were flagged in the internal design note. Resolved here:

1. **Profile location: XDG, not store-colocated.**
   `$XDG_CONFIG_HOME/llm-secrets/profiles.toml` (default `~/.config/llm-secrets/profiles.toml`).
   *Why:* `profiles.toml` is non-secret config — diffable, vimmable, dotfile-managed. The encrypted store at `~/.llm-secrets/` is the security boundary. Separating them is correct: backing up profiles via dotfiles must not risk leaking the store, and editing config must not risk corrupting the store.

2. **TTL semantics: default, not maximum.**
   `ttl` in the toml is the *default* used when no `--ttl` is passed on the command line. CLI override always wins and is unconstrained.
   *Why:* simpler, ergonomic, matches user intuition. Maximum-TTL enforcement is a session-policy concern, not a profile concern, and can be added later in `policy.rs` without touching profiles.

3. **`exec --profile` precedence over an inherited `LLM_SECRETS_MACAROON`: fresh mint always.**
   If `LLM_SECRETS_MACAROON` is set in the environment and `--profile` is also given, ignore the env macaroon and mint fresh from the profile.
   *Why:* the user's intent with `--profile` is "use this profile, now." The env-macaroon path is for callers that bring their own token via plain `exec` (no `--profile`).
   *Documented behaviour:* `exec` without `--profile` honours `LLM_SECRETS_MACAROON` as today. `exec --profile X` always re-mints. No silent fall-through.

4. **Conflict detection at load time.**
   If a profile maps two different secret keys to the same env var, error at `profile load` (i.e., on every command that reads the profile), not at exec time. Error message names both keys and the offending env var.
   *Why:* loud, fast, no silent overwrites. The user finds out at `profile show`, not at 3am during a deploy.

5. **Phase 1 supports a single `profiles.toml`. `profiles.d/` is Phase 2.**
   *Why:* simpler to ship; per-machine override is a real but secondary need; can be added compatibly.

6. **No `EnvMap` macaroon caveat in Phase 1.**
   *Why:* the env mapping lives in the toml and is consumed by the CLI. A delegated macaroon does not need to carry the env mapping unless the receiver is on a different machine and lacks the toml — that's a Phase 2 concern, and only if cross-machine delegation becomes a real workflow.

7. **"No active session" UX fix is in scope for this ADR.**
   `exec --profile` (and `profile mint`) currently fails with:
   `error: policy denied access to 'X': no active session and no macaroon presented — run 'llms session-start'`
   This message is correct but reads as a stack-trace. The new message:
   `error: no active session — run 'llms session-start' (or 'llms session-start --ttl 8h')`
   is plain English and includes the suggested fix.

## Errors

```
error: no active session — run 'llms session-start'
error: profile 'iba' not found in ~/.config/llm-secrets/profiles.toml
error: profile 'iba' has conflicting env mappings: both 'iba_ad_password' and 'iba_jira_api_key' map to env var 'TOKEN'
error: profile 'iba' references unknown secret 'iba_old_password' (run 'llms list' to see available keys)
error: profile 'iba' has invalid ttl '8 hours' (expected duration like '8h', '30m', '1d')
```

The "unknown secret" check requires reading the store key list, which is *not* sensitive (it's what `llms list` already returns). It runs at `profile show / mint / exec` time, not at parse time, so a profile referencing a secret that doesn't yet exist is parseable but not usable.

## Audit

Every `profile mint` and `profile exec` writes one audit entry, the same shape as existing mint/exec entries, with an extra field:
```json
{ "op": "profile_mint", "profile": "iba", "secrets": [...], "ttl": "8h", "ctx": {...} }
{ "op": "profile_exec", "profile": "iba", "command": "iba-connect", "ctx": {...} }
```
The `command` field captures `argv[0]` only — never arguments, which may contain non-secret but sensitive context. (This matches existing exec audit behaviour.)

## Tests

- `profile::load` — happy path, missing profile, malformed toml, invalid ttl
- `profile::validate` — env-var conflict detection (positive and negative)
- `profile::to_caveats` — round-trip to `Caveat`, ttl override behaviour
- `profile mint` golden path — mints, returns macaroon parseable by existing `Macaroon::decode`
- `profile exec` golden path — env vars present in child, secrets not present in parent's environ after exec returns
- `profile exec` with `--profile` overrides inherited `LLM_SECRETS_MACAROON`
- "No active session" error path returns the new plain-English message

## What this does NOT change

- `Caveat` enum
- Macaroon serialisation
- Macaroon verification path
- Store layout (`~/.llm-secrets/`)
- Audit log shape (one new `op` value, otherwise unchanged)
- Existing `mint`, `exec`, `set`, `peek`, `list`, `delete`, `session-*`, `lease`, `macaroon`, `mcp` commands (all unchanged in behaviour)

## Phase 2 (deferred — not part of this ADR)

These are mentioned for context only. Each will get its own ADR if and when needed.

- `profiles.d/<name>.toml` directory layout for per-machine overrides
- `EnvMap` caveat for fully self-contained portable profiles (cross-machine delegation)
- Glob support in `repo` matcher (`adjoint/*`) — Phase 1 is exact match only
- Hierarchical profiles / inheritance (`iba-prod extends iba`)
- Auto-cache of recently-minted macaroons to avoid re-mint cost on hot paths
- Maximum-TTL enforcement as a session policy

## Migration

None. v2.1 is purely additive. Existing v2.0 users see no behavioural change. Profiles are opt-in.
