# TODO

**v1.0 is released.** The Rust binary implements the full workload identity model.

- **Issues**: <https://github.com/adjoint-uk/llm-secrets/issues>
- **Releases**: <https://github.com/adjoint-uk/llm-secrets/releases>
- **ADRs**: [`docs/adr/`](docs/adr/)
- **Docs**: [`docs/USAGE.md`](docs/USAGE.md), [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md)

## What's done

| Milestone | Issues | Status |
|---|---|---|
| **v0.2** — age + Rust | #1 | ✅ |
| **v0.3** — identity + policy | #4, #5, #6 | ✅ |
| **v0.4** — leases + audit + killswitch | #7, #8, #9 | ✅ |
| **v1.0** — MCP + docs + release | #10, #12, #13 | ✅ |
| CI | #11 | ✅ |
| ADRs | #14 | ✅ |
| No-`get` invariant | #2 | ✅ |
| Encryption decision | #3 | ✅ |

## What's next (v1.x)

These do not block v1.0 but are obvious next steps:

- **Strict-mode leases.** `exec --leased` (or a config flag) requires a current lease *and* sets the default to fail-closed if no lease is held.
- **`revoke-all --rotate`.** Re-encrypt the store under a fresh age key on killswitch.
- **Remote attestation anchors.** Tie session identity to something a third party trusts: signed git commits, TPM quotes, OIDC tokens from CI runners. The session file shape stays the same; only the verifier grows.
- **MCP write tools.** `set` / `delete` exposed via MCP, gated by a `mcp.write` policy field. Needs ADR.
- **Strict audit.** Fail-closed audit logging — if the log can't be written, the access fails. Currently best-effort.
- **Per-secret encryption backend.** Optional alternative to the single-file store for high-value deployments.
- **Windows file perms.** Currently the perm-setting helpers are no-ops on Windows. Should at least set ACLs.

## House rules

- One logical change per PR.
- `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test --all` is the pre-push gate. CI enforces it.
- Non-trivial design decisions become an ADR in `docs/adr/`. Number sequentially.
- New dependencies need a one-line justification in the PR description.
- Commits are SSH-signed.
- No `get` command. Ever.
