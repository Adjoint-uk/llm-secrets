# Contributing to llm-secrets

Thanks for your interest in contributing. This project is in active development — we welcome issues, discussions, and pull requests.

## Development Setup

```bash
# Clone
git clone https://github.com/adjoint-uk/llm-secrets.git
cd llm-secrets

# Build
cargo build

# Run tests
cargo test

# Run the CLI
cargo run -- --help
```

Requires Rust 1.75+ (we use edition 2024).

## Project Structure

```
src/
  main.rs       — entry point
  cli.rs        — clap command definitions and dispatch
  error.rs      — error types
```

The architecture will expand as milestones are implemented. See [milestones](https://github.com/adjoint-uk/llm-secrets/milestones) for the roadmap.

## How to Contribute

### Good First Issues

Look for issues labelled [`good first issue`](https://github.com/adjoint-uk/llm-secrets/labels/good%20first%20issue) — these are scoped, well-described tasks suitable for newcomers.

### Picking Up Work

1. Check the [milestones](https://github.com/adjoint-uk/llm-secrets/milestones) — we work in order (v0.2 → v0.3 → v0.4 → v1.0)
2. Comment on an issue to claim it
3. Fork, branch, implement, PR

### Pull Requests

- One logical change per PR
- Include tests for new functionality
- Run `cargo test` and `cargo clippy` before submitting
- Sign your commits (we use SSH signing — see [GitHub docs](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits))

### Design Principles

- **Architectural enforcement over behavioural** — if a secret shouldn't be exposed, make it impossible, not just discouraged
- **Lean and simple** — fewer dependencies, fewer moving parts
- **Workload identity first** — every feature should reinforce the identity model

## Code Style

- `cargo fmt` for formatting
- `cargo clippy` for lints
- Prefer returning `Result` over panicking
- Use `secrecy::SecretString` and `zeroize` for sensitive data in memory

## Reporting Security Issues

See [SECURITY.md](SECURITY.md).
