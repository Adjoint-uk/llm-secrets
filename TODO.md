# TODO

The single source of truth for what's open on `llm-secrets`. Anything else
(skill files, design notes) should link here, not duplicate.

- **Issues**: <https://github.com/adjoint-uk/llm-secrets/issues>
- **Releases**: <https://github.com/adjoint-uk/llm-secrets/releases>
- **ADRs**: [`docs/adr/`](docs/adr/)
- **Docs**: [`docs/USAGE.md`](docs/USAGE.md), [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md), [`docs/integration-guide.md`](docs/integration-guide.md)

## Released

| Version | Date | Theme |
|---|---|---|
| v0.2 | — | age + Rust rewrite |
| v0.3 | — | session identity + policy engine |
| v0.4 | — | leases + audit + killswitch |
| v1.0.0 | 2026-04-07 | MCP, docs, release pipeline |
| v1.1.0 | 2026-04-08 | macaroons added as a layer (superseded) |
| **v2.0.0** | **2026-04-08** | **macaroon merge — the session IS a macaroon** |
| **v2.1.0** | **2026-04-09** | **TOML profiles — the recipe layer** |

All 14 original GitHub issues are closed.

## Open — file as issues when work starts

These are the next obvious moves. None block the current release. File on
GitHub when they become real work; until then, this list is the index.

### Small / hygienic

- **Strict-mode leases.** `exec --leased` (or a config flag) requires a
  current lease *and* sets the default to fail-closed if no lease is held.
  Hook is already there: `LeaseSet::active_for` is `#[allow(dead_code)]`
  waiting for a caller. ~80 LOC.
- **Windows file ACLs.** `set_file_perms` / `set_dir_perms` are no-ops on
  Windows. Should at least set ACLs that strip group/other access. Needs a
  Windows test environment to verify.
- **`profile show` against the live store.** Optionally cross-check that
  every secret referenced by a profile actually exists in the store, with a
  yellow warning rather than an error. (ADR 0008 says this runs at mint
  time; making it visible at `show` time too is nice.)

### Needs an ADR before code

- **MCP write tools.** `set` / `delete` exposed via MCP, gated by a
  `mcp.write` policy field. Draft ADR 0009.
- **Strict / fail-closed audit.** Currently best-effort; if the audit log
  can't be written, the read still proceeds. Threat-model review needed —
  failing closed has its own DoS surface. Draft ADR 0010.
- **Per-secret encryption backend.** Optional alternative to the single-file
  store for high-value deployments. The `Store` could grow a trait with a
  second backend. Speculative — wait for a real consumer asking for it.

### v2.x — macaroon depth

- **Profile inheritance.** `iba-prod extends iba` — additive caveats only,
  never widening. Phase 2 of ADR 0008.
- **`profiles.d/` directory layout.** Per-machine overrides for the same
  profile name. Phase 2 of ADR 0008.
- **`EnvMap` caveat for cross-machine delegation.** Only if cross-machine
  delegation becomes a real workflow. Phase 2 of ADR 0008.
- **Glob support in `repo` matcher** (`adjoint/*`). Phase 2 of ADR 0008.

### v3.x — remote attestation anchors

The strategic horizon. Each is a real direction; deferred until the
landscape moves. Pick when there's a forcing function.

- **Vendor OIDC tokens (Sigstore pattern).** Anthropic / Cursor / Microsoft
  run an OIDC issuer for their dev tools; `llms` verifies the JWT against
  their JWKS. Composes naturally as a caveat type. **Blocked on vendor
  cooperation** — file the moment any vendor announces.
- **Process-tree attestation.** `llms` walks `/proc/<pid>/exe`, hashes its
  parent process chain. Catches lying `CLAUDE_CODE` env vars. Cross-platform
  pain (`/proc` vs `proc_pidpath` vs `OpenProcess`). Useful as a *secondary*
  check on top of macaroons, not as a primary identity source.
- **TPM / hardware-backed attestation.** Strong but heavy. Right answer for
  high-assurance enterprise deployments (defence, regulated finance). Wrong
  threat model for the dev-tool case. Plausibly v3.0.

These are not mutually exclusive. The right long-term shape is *macaroons
as the local trust mechanism + vendor OIDC as a caveat type + TPM as a
high-assurance opt-in*. The reason we picked macaroons first is that it's
the only one we could ship without waiting on anyone else.

## House rules

- One logical change per PR.
- `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test --all`
  is the pre-push gate. CI enforces it.
- Non-trivial design decisions become an ADR in `docs/adr/`. Number sequentially.
- New dependencies need a one-line justification in the PR description.
- Commits are SSH-signed.
- No `get` command. Ever.
- No `Co-Authored-By` lines.
