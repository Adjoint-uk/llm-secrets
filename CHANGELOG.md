# Changelog

All notable changes to `llm-secrets` will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.0]: https://github.com/adjoint-uk/llm-secrets/releases/tag/v1.0.0
[0.2.0]: https://github.com/adjoint-uk/llm-secrets/releases/tag/v0.2.0
[0.1.1]: https://github.com/adjoint-uk/llm-secrets/releases/tag/v0.1.1
