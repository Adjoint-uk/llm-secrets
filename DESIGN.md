# llm-secrets — Design & Direction

The narrative companion to the issue tracker: release history, the strategic
horizon, and the house rules. *What's open* is no longer here — it lives as
issues.

- **Live task list**: [GitHub Issues](https://github.com/adjoint-uk/llm-secrets/issues), grouped by [milestone](https://github.com/adjoint-uk/llm-secrets/milestones) — `v3.1 — strict-mode & hygiene` and `macaroon depth (v3.x)` are the active edge.
- **Releases**: <https://github.com/adjoint-uk/llm-secrets/releases>
- **ADRs**: [`docs/adr/`](docs/adr/) · **Docs**: [`docs/USAGE.md`](docs/USAGE.md), [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md), [`docs/integration-guide.md`](docs/integration-guide.md)

## Released

| Version | Date | Theme |
|---|---|---|
| v0.2 | — | age + Rust rewrite |
| v0.3 | — | session identity + policy engine |
| v0.4 | — | leases + audit + killswitch |
| v1.0.0 | 2026-04-07 | MCP, docs, release pipeline |
| v1.1.0 | 2026-04-08 | macaroons added as a layer (superseded) |
| v2.0.0 | 2026-04-08 | macaroon merge — the session IS a macaroon |
| v2.1.0 | 2026-04-09 | TOML profiles — the recipe layer |
| v2.2.0 | 2026-04-10 | (see CHANGELOG) |
| **v3.0.x** | **2026-04-10** | **XDG-compliant store location** |

The original 14 GitHub issues (v0.2–v1.0) are all closed. Near-term work
(strict-mode leases, profile/store cross-check, Windows ACLs, the MCP-write and
fail-closed-audit ADRs, and the macaroon-depth features) is filed under the
active milestones above.

## Strategic horizon — remote attestation anchors

Deliberately *not* filed as issues: these are directions, not scheduled work.
Each gets picked up when there's a forcing function, and becomes an ADR before
any code lands.

- **Vendor OIDC tokens (Sigstore pattern).** Anthropic / Cursor / Microsoft run
  an OIDC issuer for their dev tools; `llms` verifies the JWT against their
  JWKS. Composes naturally as a caveat type. **Blocked on vendor cooperation** —
  file the moment any vendor announces.
- **Process-tree attestation.** `llms` walks `/proc/<pid>/exe`, hashes the parent
  process chain. Catches lying `CLAUDE_CODE` env vars. Cross-platform pain
  (`/proc` vs `proc_pidpath` vs `OpenProcess`). Useful as a *secondary* check on
  top of macaroons, not as a primary identity source.
- **TPM / hardware-backed attestation.** Strong but heavy. Right for
  high-assurance enterprise (defence, regulated finance), wrong threat model for
  the dev-tool case.

These are not mutually exclusive. The right long-term shape is *macaroons as the
local trust mechanism + vendor OIDC as a caveat type + TPM as a high-assurance
opt-in*. Macaroons came first because they're the only one shippable without
waiting on anyone else.

## House rules

- One logical change per PR.
- `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test --all`
  is the pre-push gate. CI enforces it.
- Non-trivial design decisions become an ADR in `docs/adr/`. Number sequentially.
- New dependencies need a one-line justification in the PR description.
- Commits are SSH-signed.
- No `get` command. Ever.
- No `Co-Authored-By` lines.
