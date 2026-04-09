# Changelog

All notable changes to `llm-secrets` will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.1] — 2026-04-09

Docs + help-text polish. No behavioural changes; safe upgrade from 2.1.0.

### Changed

- **README**: profile-first quickstart. The new `llms profile exec <name>` ergonomic is now the leading example, before the manual `macaroon mint` flow. Commands table grew sections for v2.0 macaroons and v2.1 profiles.
- **`llms --help`**: `macaroon` and `profile` subcommand descriptions tightened — no more `See docs/adr/...` tails in user-facing help. ADR references stay in code comments.
- **README status section** updated to v2.1.

## [2.1.0] — 2026-04-09

**TOML profiles — the recipe layer.** v2.1 adds named profiles that group secrets and env-var mappings into a reusable recipe, eliminating wrapper-script boilerplate when consuming secrets from many tools. Profiles are config (TOML, editable, dotfile-managed); the macaroon they produce is still the unforgeable, time-bounded token. **Two layers, two concerns** — see ADR 0008.

Purely additive. v2.0 users see no behavioural change. The macaroon code path is unchanged.

### Added

- `src/profile.rs` — `Profile` type, `load`, `list`, `validate`, `to_caveats`. ~310 LOC.
- `llms profile list` — list profiles defined in `profiles.toml`.
- `llms profile show <name>` — secrets, env mapping, ttl, caveats.
- `llms profile mint <name> [--ttl X]` — print `export LLM_SECRETS_MACAROON=...`.
- `llms profile exec <name> [--ttl X] -- <cmd>` — mint + exec with env vars injected.
- `llms exec --profile <name>` — alias for `profile exec`.
- `LLM_SECRETS_CONFIG_DIR` env var — overrides the profile config directory (default `$XDG_CONFIG_HOME/llm-secrets`). Mostly for tests; real users edit `~/.config/llm-secrets/profiles.toml`.
- `revoke-all --rotate` — actually re-encrypts the store under a fresh age key now (was `not implemented yet` in v2.0). New `store::rotate_age_key()`.
- Audit events: `profile.mint`, `profile.exec`.
- 15 new tests (profile unit + integration + rotate + friendly-error).

### Changed

- `Error::NoSession` message is now plain English with the suggested fix: *"no active session — run `llms session-start` (or `llms session-start --ttl 8h`)"*. The `gate()` no longer wraps it in `PolicyDenied` — `NoSession` bubbles up directly. (ADR 0008 open question 7.)
- `llms exec` no longer requires `--inject` when `--profile` is given. The two are mutually exclusive.

### Architectural notes

- The macaroon code (`src/macaroon.rs`, `Caveat` enum, signature chain, verification) is **completely unchanged**. v2.1 is one new module + CLI glue.
- The env mapping lives **only** in the TOML, never in a caveat. Cross-machine delegation (where the receiver lacks the toml) is a Phase 2 concern; if it ever becomes a real workflow we'd add an `EnvMap` caveat then.
- `profiles.toml` confers no authority. Stealing it gets you a list of secret names — no access. Macaroons remain the only bearer authority and are still short-lived and context-restricted.

### Tests

- Total: 52 (26 unit + 26 integration), up from 37 in v2.0.

## [2.0.0] — 2026-04-08

**One primitive: the session is a macaroon.** v2.0 collapses the two parallel identity concepts (Ed25519-signed sessions and HMAC-chained macaroons) into a single object. The dev's session is the **root macaroon**. A delegated agent token is a **child macaroon derived from that root**. There is no other identity object in the system.

This is a breaking change. v1.0/v1.1 session files do not parse. Adoption was essentially zero (we shipped v1.0 less than 24 hours ago) so the cost is small.

### The unified model

- `session.json` now contains a `Macaroon` (the dev's root). Its caveats describe the dev's current context: `WhoEq`, `RepoEq`, `BranchEq`, `AgentEq`, `ExpiresAt`. Same enum, same on-disk format as a delegated child token.
- `macaroon_root.key` → `root.key` (the HMAC root key for the only "root" in the system).
- A delegated token is `root.delegate(extras)` — the HMAC chain extends from the root's signature, the child carries all the root's caveats *plus* the new ones, and verification needs only the same root key.
- Every command that reads a secret value (`peek`, `exec --inject`, `lease`) goes through one gate that requires either the dev's root macaroon (loaded automatically from `session.json`) or an explicit `--macaroon` / `LLM_SECRETS_MACAROON`. **There is no ungated read path.**
- Caveats are evaluated against a fresh `Context` built from the environment on every operation. There is no stored claim set to drift from reality.

### Breaking changes

- `session.json` format changed (now a `Macaroon` JSON, not an Ed25519-signed claim envelope). v1.x users must `llms session-start` once after upgrading.
- `macaroon_root.key` renamed to `root.key`.
- `peek`, `exec --inject`, and `lease` now **require** an active session (or a presented macaroon) — the v1.0 "permissive when no policy file" path is gone.
- Audit event types: `peek` / `peek.macaroon` are now `peek` / `peek.delegated`. `exec.inject.macaroon` is now `exec.inject.delegated`. The suffix tells you whether the read used the dev's root or a delegated child.
- The `require_macaroon` config flag from v1.2 (never released) is gone — strict mode is now the only mode.

### Removed

- `src/identity.rs` (~320 LOC) — the entire `Session`/`Claims`/Ed25519-signing module. Folded into `macaroon.rs`.
- `src/config.rs` (~110 LOC) — the strict-mode flag. Strict is now the default and only mode.
- `ed25519-dalek` dependency, plus the transitive `curve25519-dalek` and `x25519-dalek` from the signing path. The only signature primitive in the system is HMAC-SHA256.
- Net: **~280 LOC removed** from the trust layer.

### Added

- ADR 0007 documents the merge: rationale, deletions, semantics, migration.
- Five new properties tested by the unified `hmac_chain_properties` test: tamper detection across substituted/dropped/reordered caveats, escalation prevention by removing caveats, and **delegation chain extension** (a child verifies through the same root key as its parent).
- `Context::current()` — gathers fresh claims from `git config`, `$PWD`, env vars on every read. One value type for both policy and macaroon evaluation.

### Migration

```bash
# After cargo install llm-secrets --version 2.0:
llms session-start --ttl 1h
# Your store, secrets, and audit log are unchanged. session.json was
# rewritten in the new format, root.key replaces macaroon_root.key, any
# v1.1 macaroons are gone (they would have been ephemeral anyway).
```

## [1.1.0] — 2026-04-08

The dev no longer grants the agent the session's full identity. They **delegate** a slice of it as an attenuated capability.

### Added

- **Macaroon-based capability delegation.** A new `llms macaroon` subcommand mints, inspects, and verifies bearer tokens that scope what their holder can do (`--secret`, `--ttl`, `--repo`, `--branch`, `--agent`, `--who`). The dev mints; the agent inherits the token via `--macaroon` or `LLM_SECRETS_MACAROON`. The token holder cannot escalate — every caveat is enforced by an HMAC-SHA256 chain.
- `peek`, `exec`, and `lease` grow a `--macaroon` flag (also honoured: `LLM_SECRETS_MACAROON` env var). When a macaroon is presented, it must verify *in addition to* the existing policy check — never instead of it.
- Macaroon usage is audited: `peek.macaroon` and `exec.inject.macaroon` events appear in the audit log alongside the existing event types.
- **`revoke-all` is now the macaroon killswitch too.** Deleting the per-session HMAC root key invalidates every derived macaroon in O(1).
- ADR 0006 documents the capability-delegation design, the wire format, the cryptographic construction, and what is *not* in v1.1 (stateful caveats, third-party caveats, agent-side attenuation — all deferred).
- 8 new tests (5 unit + 3 CLI integration), including HMAC chain tamper detection and the **escalation-prevention property** (the defining macaroon guarantee, regression-tested). Total: 44 tests.

### Changed

- `session-start` now generates a fresh per-session macaroon HMAC root key. Old sessions' macaroons no longer verify against the new session — restarting the session is itself a soft revocation.
- `revoke-all`'s output line now mentions the macaroon root key alongside leases and the session.

### Dependencies

- Added: `hmac = "0.12"`, `sha2 = "0.10"`, `subtle = "2"` — all from [RustCrypto](https://github.com/RustCrypto), all minimal, all justified for the HMAC-SHA256 chain construction. Constant-time signature comparison via `subtle::ConstantTimeEq` to avoid timing oracles.

### Notes for users

- v1.0 flows are completely unchanged. Macaroons are opt-in; without `--macaroon` or the env var, every command behaves exactly as before.
- The macaroon wire format is **experimental in v1.1**. We may break it in v1.2 if real-world usage exposes a problem. Treat tokens as ephemeral, not durable.

## [1.0.0] — 2026-04-07

The Rust rewrite is complete and the workload identity model is fully wired.

### Added

- **v0.2 — encrypted store.** `init`, `list`, `peek`, `set`, `delete`, `status`, `exec` against an age-encrypted JSON store. `set --stdin` for pipes. ADR 0003 documents the layout. Closes #1.
- **v0.3 — session identity, policy, agent detection.** `session-start` / `session-info` produce a tamper-evident, time-bounded, locally-signed claim file. `.llm-secrets-policy.yaml` is parsed from the git root and enforced on every read (`peek`, `exec`, `lease`). Allow-list semantics with optional list-valued and wildcard fields. Agent type is auto-detected from environment variables (claude-code, cursor, github-copilot, aider, continue, windsurf). ADR 0004. Closes #4, #5, #6.
- **v0.4 — leases, audit log, killswitch.** `lease` records a time-bounded, session-anchored grant. `leases` lists active. `audit` reads back the JSONL log of every secret access (`peek` and `exec --inject` audit best-effort whenever a session is active). `revoke-all` clears every lease and the active session. Closes #7, #8, #9.
- **v1.0 — MCP server, docs, release pipeline.**
  - `llms mcp` runs a hand-rolled JSON-RPC 2.0 server on stdio (no SDK dependency). Exposes `list_secrets`, `peek_secret`, `audit_recent`, `status`. **No tool returns plaintext.** ADR 0005. Closes #10.
  - `docs/USAGE.md` — full command walkthrough.
  - `docs/SECURITY-MODEL.md` — threat model and architectural guarantees.
  - `.github/workflows/release.yml` — multi-arch binary builds (Linux x86_64/aarch64, macOS x86_64/aarch64) on tag push, plus GitHub Release attachment and crates.io publish. Closes #12, #13.
- **Quality and contribution-readiness:** issue and PR templates, code of conduct, CI badges, CONTRIBUTING.md, SECURITY.md disclosure policy. CI runs fmt + clippy `-D warnings` + tests on Linux and macOS on every push and PR.
- **Tests**: 33 (18 unit + 15 CLI integration). Round-trip coverage for the encrypted store, session signing/verification, policy evaluation, lease grant/revoke, audit log read/write, and the MCP server end-to-end including the no-plaintext invariant.

### Removed

- The Python implementation (`src/llm_secrets/`, `pyproject.toml`, Python tests). The Rust rewrite is the only path forward.
- The blanket `#[allow(dead_code)]` on the `Error` enum (only the three v1.x reserved variants remain allowed).

### Architectural

- ADR 0001 — Rust rewrite rationale.
- ADR 0002 — architectural removal of the `get` command (no `Get` variant in the CLI enum, regression-tested).
- ADR 0003 — single-file age-encrypted store layout.
- ADR 0004 — local session identity with Ed25519 attestation.
- ADR 0005 — MCP server scope (subset of CLI, no plaintext-returning tools).

## [0.2.0] — 2026-03-22

### Changed

- Began the Rust rewrite. CLI surface scaffolded with `clap`; command bodies are stubs pending implementation.

## [0.1.1] — earlier

- Final Python release. SOPS wrapper. Superseded by the Rust rewrite.

[2.0.0]: https://github.com/adjoint-uk/llm-secrets/releases/tag/v2.0.0
[1.1.0]: https://github.com/adjoint-uk/llm-secrets/releases/tag/v1.1.0
[1.0.0]: https://github.com/adjoint-uk/llm-secrets/releases/tag/v1.0.0
[0.2.0]: https://github.com/adjoint-uk/llm-secrets/releases/tag/v0.2.0
[0.1.1]: https://github.com/adjoint-uk/llm-secrets/releases/tag/v0.1.1
