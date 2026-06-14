# ADR 0010 — Audit durability: best-effort by default, opt-in fail-closed

- **Status**: Accepted
- **Date**: 2026-06-13
- **Builds on**: ADR 0004 (session identity); leases & audit (#7/#8)
- **Implemented in**: decision only — implementation tracked in #26.

## Context

Every secret access is meant to leave an audit record (`lease::audit`). Today
the access-path call sites discard the result:

```rust
let _ = crate::lease::audit("exec.inject", &ctx, None); // src/cli.rs
let _ = lease::audit("mcp.peek", &ctx, None);           // src/mcp.rs
```

So a read **succeeds even if its audit entry cannot be written** — the current
behaviour is fail-**open**, despite the `audit()` doc comment implying the
opposite. #19 asks whether we should fail **closed**: refuse the operation when
the access cannot be recorded.

### The tradeoff

- **Fail-closed** guarantees "no unlogged access" — valuable for high-assurance
  and compliance deployments. But it introduces a **denial-of-service surface**:
  a full disk, a read-only filesystem, or a permissions slip on the audit path
  makes *every* secret inaccessible. The audit log becomes a single point of
  failure for availability.
- **Fail-open** preserves availability but permits unlogged access in exactly
  those failure modes.

### What we considered

- **Always fail-closed.** Strong guarantee, but the DoS surface is the wrong
  default for the common dev-tool case (a developer's laptop, CI runner).
- **Always fail-open.** The status quo; no integrity guarantee for compliance.
- **Fail-open default + opt-in strict.** Each consumer picks the tradeoff.

## Decision

**Fail-open stays the default; add an opt-in strict (fail-closed) mode.**

- The default secret-access path remains best-effort: an audit-write failure is
  swallowed (with a warning on stderr) and the operation proceeds. This keeps
  availability and avoids the DoS surface for the common case.
- Opt-in via **`LLM_SECRETS_AUDIT_STRICT=1`**: on the secret-access path, an
  audit-write failure propagates and the operation fails **closed**. For
  high-assurance deployments that need a hard "no unlogged access" guarantee.
- Access-path audits route through a `record()` helper that honours strict mode;
  the `audit()` doc comment is corrected to describe the real (fail-open)
  default.

This mirrors the opt-in **strict-leases** model (ADR-consistent): safe,
available default; one switch for the stricter posture. As with leases, a future
major version can flip the default if the landscape calls for it.

Scope note: this applies to *secret-access* audits (`exec.inject`, `mcp.peek`).
Post-hoc audits of actions that already completed (mint, lease-grant, revoke) are
out of scope — failing them closed after the fact buys nothing.

## Consequences

- Default behaviour is unchanged; no new DoS surface for existing users.
- High-assurance users get a hard guarantee via a single environment variable.
- The doc/behaviour mismatch in `audit()` is resolved.
- Implementation is tracked separately (#26); this ADR is the decision only.
