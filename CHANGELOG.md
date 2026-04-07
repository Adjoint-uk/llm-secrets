# Changelog

All notable changes to `llm-secrets` will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Functional v0.2 commands** — `init`, `list`, `peek`, `set`, `delete`, `status`, `exec` are all implemented against an age-encrypted on-disk store. Closes #1.
- `set --stdin` reads the value from stdin (handy for pipes and scripted setup).
- ADR 0003 — on-disk store layout (single-file age-encrypted JSON).
- 14 tests covering masking, in-memory store ops, init/list/peek/set/delete round-trip, exec env injection, and CLI invariants.
- Issue and PR templates, code of conduct, CI badge.
- ADR 0001 — Rust rewrite rationale.
- ADR 0002 — architectural removal of the `get` command.
- CI workflow: fmt, clippy, test, release build on Linux and macOS.
- Integration tests asserting CLI invariants (`tests/cli.rs`).
- `SECURITY.md` disclosure policy.

### Removed

- The Python implementation (`src/llm_secrets/`, `pyproject.toml`, Python tests). The Rust rewrite is the only path forward.

### Changed

- `.gitignore` cleaned of Python noise.

## [0.2.0] — 2026-03-22

### Changed

- Began the Rust rewrite. CLI surface scaffolded with `clap`; command bodies are stubs pending implementation.

## [0.1.1] — earlier

- Final Python release. SOPS wrapper. Superseded by the Rust rewrite.

[Unreleased]: https://github.com/adjoint-uk/llm-secrets/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/adjoint-uk/llm-secrets/releases/tag/v0.2.0
[0.1.1]: https://github.com/adjoint-uk/llm-secrets/releases/tag/v0.1.1
