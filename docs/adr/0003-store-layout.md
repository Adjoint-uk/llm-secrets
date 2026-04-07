# ADR 0003 — On-disk store layout

- **Status**: Accepted
- **Date**: 2026-04-07
- **Relates to**: #1

## Context

v0.2 needs an on-disk encrypted store. Options considered:

1. **Single age-encrypted file** containing a JSON map `{key: value, ...}`.
2. **One file per secret**, each independently age-encrypted.
3. **SQLite database** with per-row encryption.

Tradeoffs:

| | Single file | File-per-secret | SQLite |
|---|---|---|---|
| Atomic rekey | ✅ trivial | ❌ multi-file dance | ✅ |
| Audit / inspection | ✅ one file | ❌ many files | ❌ binary blob |
| `list` cost | Decrypt whole | List dir | Query |
| Per-secret blast radius if leaked | Whole store | One secret | One row |
| Implementation cost | Tiny | Moderate | High (new dep) |
| Backups / sync | Trivial | Multi-file | Binary diffs |

## Decision

**Single age-encrypted file** holding a JSON map of `name → secret`. Two files in the store directory:

```
$LLM_SECRETS_DIR/    (default: ~/.llm-secrets/, mode 0700)
├── identity.txt     (age x25519 secret key, mode 0600)
└── store.age        (age-encrypted JSON, mode 0600)
```

`$LLM_SECRETS_DIR` overrides the default (used by tests).

Writes are **atomic** via write-to-`.tmp` + `rename`.

## Consequences

### Positive

- Tiny implementation, no new dependencies beyond what `Cargo.toml` already declares.
- Rekey / rotate is one decrypt + one re-encrypt of one file. Killswitch (#9) becomes trivial.
- Listing keys requires decrypting the store, which means **`list` is gated by holding the identity**. We will not need a separate "metadata" file that leaks key names without the key.
- The whole store is small (human-scale: tens to low hundreds of secrets). Decrypt cost is microseconds.

### Negative

- Any operation that reads the store transiently holds **all** plaintext in process memory. Mitigation: drop the `Store` struct as soon as the operation completes; `secrecy::SecretString` for hot values; `zeroize` on drop where it matters. v0.4's lease model further bounds the window.
- The blast radius of a leaked plaintext is the whole store, not one secret. For v0.2 this is acceptable — anyone who can read process memory has already lost. For high-value deployments, per-secret encryption can ship later as an opt-in store backend without changing the CLI.

### Future

If per-secret encryption becomes needed, the `Store` trait can grow a second backend implementation. The CLI surface and serialised JSON stay the same.
