# ADR 0004 — Session identity and attestation

- **Status**: Accepted
- **Date**: 2026-04-07
- **Closes**: #4

## Context

`llm-secrets` needs to know **who is asking** before it can apply a policy. The README's promise:

```
who:   cptfinch                 (from git config)
where: adjoint-uk/billing, main (from git remote + branch)
what:  Claude Code, pid 12345   (from agent detection)
when:  2026-04-07T11:00:00Z     (now)
```

These are **claims**, gathered locally and signed by an **ephemeral session keypair**. The signature does not prove anything to a third party — there is no remote trust anchor in v0.3 — but it does prove **continuity within a session**: a process holding a session file can demonstrate it owned the key when the session started.

This is the floor of the workload identity model. v1.x can grow remote attestation (TPM, hardware keys, signed git commits) on top.

## Decision

A **session** is a JSON file at `$LLM_SECRETS_DIR/session.json` containing:

```json
{
  "claims": {
    "who":  "cptfinch",
    "repo": "adjoint-uk/llm-secrets",
    "branch": "main",
    "agent": "claude-code",
    "pid": 12345,
    "started_at": "2026-04-07T19:35:00Z",
    "expires_at": "2026-04-07T20:35:00Z"
  },
  "public_key": "<base64 ed25519 public key>",
  "signature":  "<base64 signature over canonical JSON of claims>"
}
```

`llms session-start [--ttl 1h]`:

1. Generates a fresh Ed25519 keypair.
2. Gathers claims (best-effort — every field can be missing).
3. Serialises `claims` as canonical JSON (sorted keys, no whitespace).
4. Signs that byte string with the private key.
5. Writes the session file (mode 0600).
6. **Drops the private key.** It is not persisted.

`llms session-info`:

1. Reads the session file.
2. Verifies the signature against the embedded public key.
3. Checks `expires_at` against now.
4. Prints the claims.

Once the private key is dropped, no new claims can be added to this session — only verified.

## Consequences

### Positive

- Claims are tamper-evident: editing `session.json` by hand invalidates the signature.
- The public key travels with the session, so verification needs nothing else.
- Ephemeral keys mean a leaked session file cannot be reused to forge new sessions.
- Aligns with the policy engine in #5 — every store operation can ask "what does the active session claim?".

### Negative

- Local only. The signature is not anchored to anything a remote party trusts. v0.3 is "honest accounting", not unforgeable.
- A malicious local actor with write access to `$LLM_SECRETS_DIR` can replace the session file with one of their own. This is acceptable: anyone with that level of access has already lost.
- Session files persist on disk until expiry. v0.4's killswitch (#9) revokes them.

### Future

v1.x: tie session start to a real attestation source (a signed commit, a TPM quote, an OIDC token from a CI runner). The session file format does not need to change — only the trust evaluator does.
