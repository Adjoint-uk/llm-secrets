# ADR 0001 — Rewrite in Rust

- **Status**: Accepted
- **Date**: 2026-03-22
- **Closes**: #14

## Context

`llm-secrets` started life as a Python wrapper around the [SOPS](https://github.com/getsops/sops) CLI (v0.1.x). Two problems pushed us to reconsider:

1. **Python deployment is the wrong shape for a security tool.** Users need pip, a working interpreter, and a venv. For something that should drop into a developer's `$PATH` and Just Work, this is friction we cannot accept.
2. **SOPS is the wrong abstraction for v0.3+.** SOPS adds an external runtime dependency and a second config surface (`.sops.yaml`). It does not model workload identity, leases, attestation, or audit — all of which the project needs by v1.0. We would end up reimplementing most of SOPS's responsibilities anyway.

## Decision

Rewrite as a single static Rust binary using:

- [`age`](https://crates.io/crates/age) — X25519 + ChaCha20-Poly1305 encryption (replaces SOPS)
- [`clap`](https://crates.io/crates/clap) — CLI parsing
- [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) — session attestation keys (v0.3)
- [`secrecy`](https://crates.io/crates/secrecy) + [`zeroize`](https://crates.io/crates/zeroize) — in-memory hygiene for plaintext

Distribution via `cargo install llm-secrets` initially, prebuilt release binaries for v1.0.

## Consequences

### Positive

- One static binary. No runtime to install, easy to verify and audit.
- Direct control of the encryption surface — no SOPS YAML quirks, no shell-out.
- The type system enforces invariants. The `Command` enum has no `Get` variant, so "expose a raw secret to stdout" is not a code path that exists. (This is the architectural enforcement principle the README points at.)
- Aligns with v0.3+ workload identity work, which needs tight control over key material and process boundaries.

### Negative

- We lose any existing Python users. Acceptable: pre-1.0, very small surface.
- Slower iteration than Python during early development. We accept this in exchange for the deployment story.
- Binary distribution story (signing, multi-arch releases) is deferred to v1.0 (#13).

## Related

- ADR 0002 (planned) — Architectural removal of `get`. Closes #2.
