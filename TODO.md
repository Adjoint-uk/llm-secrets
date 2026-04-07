# TODO

Active work is tracked as GitHub issues and milestones — this file is just a pointer.

- **Issues**: <https://github.com/adjoint-uk/llm-secrets/issues>
- **Milestones**: <https://github.com/adjoint-uk/llm-secrets/milestones>
- **ADRs**: [`docs/adr/`](docs/adr/)

## Current focus — v0.2: Rust rewrite + age encryption

The CLI surface is scaffolded in `src/cli.rs` (clap, all commands defined). The command bodies are still `println!("TODO: ...")` placeholders.

**Next concrete step:** implement `llms init` and the on-disk store layout — issue #1.

## Roadmap at a glance

| Milestone | Issues | Status |
|---|---|---|
| **v0.2** — age + Rust | #1 | In progress (CLI scaffolded; store impl pending) |
| **v0.3** — identity + policy | #4, #5, #6 | Not started |
| **v0.4** — leases + audit + killswitch | #7, #8, #9 | Not started |
| **v1.0** — MCP + docs + release | #10, #12, #13 | #11 (CI) ✅ done |

## Recently closed

- **#2** — Removed `get` command. Architecturally enforced + regression-tested in `tests/cli.rs`. See ADR 0002.
- **#3** — Decided on the `age` Rust crate over `pyage` / shelling out to `age` CLI. Locked in via `Cargo.toml`.
- **#11** — CI workflow added (fmt + clippy + test on Linux & macOS).
- **#14** — Rust rewrite ADR. See `docs/adr/0001-rust-rewrite.md`.

## House rules

- One logical change per PR.
- `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test` must pass before pushing.
- No `get` command. Ever. (See ADR 0002.)
