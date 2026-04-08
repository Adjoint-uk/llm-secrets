# ADR 0007 — One primitive: the session is a macaroon

- **Status**: Accepted
- **Date**: 2026-04-08
- **Supersedes**: parts of ADR 0004 (the Ed25519 session model)
- **Builds on**: ADR 0006 (the macaroon design)

## Context

v1.0 shipped two parallel identity concepts:

1. **`session.json`** — the dev's identity, signed by an ephemeral Ed25519 keypair (ADR 0004). Carried `claims` (who/repo/branch/agent/pid/started_at/expires_at).
2. **Macaroons** (added in v1.1, ADR 0006) — bearer tokens for delegated capability, with their own HMAC-SHA256 chain and a separate root key.

This was structurally honest: macaroons were a *layer on top of* the session model. But it left two distinct trust objects in the system, with two file formats, two cryptographic primitives (Ed25519 + HMAC), and two mental models for users to learn. The README's positioning of macaroons as the core idea was at odds with the code, where they were one feature among several.

## Decision

In v2.0, **the session IS a macaroon**. There is one identity primitive in the entire trust model.

- `session.json` now contains a `Macaroon` (the dev's **root macaroon**), in exactly the same on-disk format as a delegated child token.
- Caveats on the root macaroon describe the dev's current context: `WhoEq`, `RepoEq`, `BranchEq`, `AgentEq`, `ExpiresAt`. They are the same `Caveat` enum used by delegated tokens.
- A delegated token is just `root.delegate(extras)` — the HMAC chain extends from the root's signature, the child carries all the root's caveats *plus* the new ones, and verification needs only the same root key.
- The HMAC root key file is renamed `macaroon_root.key` → `root.key` to reflect that there is no other "root" in the system.

### What got deleted

- `src/identity.rs` — the entire `Session`, `Claims`, Ed25519-signing module. Gone.
- `src/config.rs` — the `require_macaroon` strict-mode flag. Strict is now the only mode.
- `ed25519-dalek` dependency. We don't sign anything with Ed25519 anymore — HMAC-SHA256 is the only signature in the system.

### What got unified

- `Context` is now built fresh from the environment on every operation, via `Context::current(key)`. It carries the request `key` plus the same who/repo/branch/agent fields the caveats compare against. It is no longer a stored object — it's a one-shot value built at the gate.
- Both the policy engine (`policy::check_access`) and the macaroon verifier (`Macaroon::verify`) take `&Context`. One type, both gates.
- `lease::audit` takes `&Context` and gathers `pid` from `std::process::id()` — the audit log shape is unchanged on disk.

### The read gate

Every command that reads a secret value passes through one helper:

```rust
fn gate<'a>(key: &'a str, flag: &Option<String>) -> Result<Context<'a>> {
    let ctx = Context::current(key);
    policy::check_access(&ctx)?;
    let m = pick_macaroon(flag)
        .map(|s| Macaroon::decode(&s))
        .transpose()?
        .or_else(|| Macaroon::load_root().ok())
        .ok_or_else(|| Error::PolicyDenied { ... })?;
    m.verify(&ctx)?;
    Ok(ctx)
}
```

There is no "ungated" read path. If neither an explicit token nor a root macaroon is available, the operation fails closed.

## Consequences

### Positive

- **One primitive.** The README's claim — *"the first secrets manager built around capability delegation"* — is now structurally true rather than aspirationally true. There is no other identity object to fall back to.
- **Less code.** `identity.rs` (~320 LOC) and `config.rs` (~110 LOC) are gone. `macaroon.rs` grew by ~150 LOC to absorb the gathering logic. Net: **roughly 280 LOC removed**.
- **Lean dependencies.** `ed25519-dalek` (and its transitive `curve25519-dalek`, `x25519-dalek` for the signing path) is dropped. The only signature primitive is HMAC-SHA256 from RustCrypto.
- **Verification semantics are simpler.** A caveat is checked against the *current* environment, not against a stored claim set. There is no "session has claims, macaroon has caveats" duality to teach.
- **The killswitch is even simpler.** `revoke-all` deletes `root.key` and `session.json`. Every token (root and derived) becomes unverifiable in O(1).
- **Cleaner audit semantics.** Audit events are `peek`, `peek.delegated`, `exec.inject`, `exec.inject.delegated` — the suffix tells you whether the access used the dev's root or a delegated child.

### Negative

- **Breaking change.** v1.0/v1.1 `session.json` files do not parse — they had a different shape (Ed25519-signed claims vs. macaroon JSON). Existing users have to run `llms session-start` once after upgrading. Adoption is essentially zero (we shipped v1.0 less than 24 hours before this ADR), so the cost is real but tiny.
- **No more "private key dropped after one signing"** semantic from ADR 0004. The HMAC root key persists for the lifetime of the session. This is a real loss of one defence-in-depth property — but it's bought back by the same property macaroons already have: **caveats cannot be added or removed without breaking the chain**, so a leaked root macaroon file cannot be widened or extended; the only thing an attacker can do with it is *use it as-is*, which is exactly the same situation a leaked Ed25519 session file already faced in v1.0. Net: no real loss.
- **The Ed25519 attestation path that ADR 0004 hinted at** (signing a quote against a remote anchor) goes away. We can grow the same shape back as a *third-party caveat* on the macaroon when vendor OIDC arrives — see ADR 0006's "third-party caveats" deferred section. The path forward is unchanged; only the v1.x intermediate is gone.

### Future

- **Strict-mode** is now the default and only mode. The old `require_macaroon` config flag is unnecessary because there is no permissive mode to opt out of.
- **Vendor OIDC** integration (the Sigstore-shaped destination — see contributor skill) becomes a new caveat type added to the existing enum. No format change, no new file, no new primitive.
- **`--rotate` for the killswitch** (re-encrypting the store under a fresh age key) is still on the v1.x ideas list and now even simpler to wire up because there's only one identity object to invalidate.

## Migration note for the (very few) v1.0/v1.1 users

```bash
# After upgrading to 2.0:
llms session-start --ttl 1h
# That's it. Your store and secrets are unchanged. The session.json file
# was rewritten in the new format, the new root.key replaces the old
# macaroon_root.key, and any v1.1 macaroons you had outstanding are gone
# (they would have been ephemeral anyway).
```
