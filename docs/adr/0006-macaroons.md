# ADR 0006 — Macaroon-based capability delegation

- **Status**: Accepted
- **Date**: 2026-04-08
- **Closes**: (no original issue — this is the v1.x north-star direction the contributor skill records)
- **Supersedes**: nothing (composes with ADR 0004)

## Context

v1.0 ships with **session identity**: a locally-signed, time-bounded claim file (`session.json`) gathering who/where/what/when. The policy engine evaluates secret reads against the active session's claims.

That works, but it has a structural weakness: **the agent and the session are conflated**. Whichever process holds the session file gets the full session's authority. A long-running session that happens to be active when an untrusted subagent spawns is, in effect, granting that subagent everything the developer can see.

What we actually want is the semantics from the contributor skill's strategic note:

> The dev should *delegate a slice of their identity* to the agent, not *grant* the agent its own.

That is the macaroon shape. Macaroons (Birgisson et al., 2014, building on Mark S. Miller's capability work) are bearer tokens with two distinguishing properties:

1. **The holder can attenuate** — add restrictions ("caveats") and derive a new, weaker token, without contacting the issuer.
2. **The holder cannot escalate** — every caveat is enforced, and the signature chain prevents removing one.

This is exactly the right shape for a developer who wants to say *"I'm letting an untrustworthy thing act on my behalf, briefly, narrowly."*

## Decision

Add a **macaroon layer** on top of the existing session model. Macaroons are minted from a per-session HMAC root key, attenuated with caveats, and presented to `peek` / `exec` / `lease`. The session model stays as the *trust anchor* — macaroons are only valid within an active session.

### Wire format

A macaroon is a JSON envelope, base64url-encoded into a single safe-to-paste string:

```json
{
  "id": "<base64 16-byte random id>",
  "location": "llm-secrets://localhost",
  "caveats": [
    { "type": "secret_eq", "value": "db_password" },
    { "type": "expires_at", "value": "2026-04-08T13:00:00Z" },
    { "type": "agent_eq", "value": "claude-code" }
  ],
  "signature": "<base64 32-byte HMAC-SHA256>"
}
```

### Cryptographic construction

Standard macaroon HMAC chain:

```
sig_0 = HMAC-SHA256(root_key, id)
sig_n = HMAC-SHA256(sig_{n-1}, canonical_bytes(caveat_n))
```

The final `sig_n` is the macaroon's `signature` field. To verify: recompute the chain from `root_key` + `id` + `caveats[]` and constant-time-compare against the stored signature. Tampering with any caveat breaks the chain. Removing or reordering caveats breaks the chain.

`canonical_bytes(caveat)` is the JSON serialisation with sorted keys (we already have the helper from `identity::canonical_json`).

### The root key

A per-session 32-byte random secret stored at `$LLM_SECRETS_DIR/macaroon_root.key` (mode 0600) created on `session-start`. The file is deleted by:

- `session-start` (overwritten with a fresh key on every new session)
- `revoke-all` (the existing killswitch — nukes the root key, instantly invalidating every derived macaroon ever issued from this session)

Why a separate file rather than reusing the session's Ed25519 material?

- The session's private key is **dropped after signing** (ADR 0004) — there is nothing left to derive from.
- HMAC and Ed25519 are different primitives with different key shapes; conflating them is asking for trouble.
- Having a separate file makes the killswitch explicit: "delete the root key" is one `unlink` and is easy to reason about.

### Caveat language (v1.1)

Caveats are stateless predicates evaluated against the **current request context** at verification time:

| Type | Meaning | Verified against |
|---|---|---|
| `secret_eq` | Restrict to one named secret | The key being requested |
| `secrets_in` | Restrict to a list of named secrets | The key being requested |
| `expires_at` | Token invalid after this RFC3339 timestamp | Wall clock |
| `repo_eq` | Token only valid in this repo | Active session's `claims.repo` |
| `branch_eq` | Token only valid on this branch | Active session's `claims.branch` |
| `agent_eq` | Token only valid for this detected agent | Active session's `claims.agent` |
| `who_eq` | Token only valid for this user | Active session's `claims.who` |

**Stateful caveats are deferred** to v1.2:

- `pid_eq` is stateless but `pid_alive` requires probing — defer.
- `one_shot` requires marking the macaroon spent — needs a state file. Defer.
- Third-party caveats (the macaroon paper's "discharge" mechanism for chained authorization) are out of scope until vendor OIDC is real.

### CLI surface

Three new subcommands under `llms macaroon`:

```bash
llms macaroon mint \
    --secret db_password \
    --ttl 5m \
    --agent claude-code
# → prints a single base64url string to stdout

llms macaroon inspect [--macaroon <b64>]
# → human-readable dump of caveats. Reads from stdin or --macaroon if not given.
# → never touches the secret store; pure parse.

llms macaroon verify [--macaroon <b64>]
# → exit 0 if signature + caveats hold against current context, exit 1 otherwise.
```

`peek`, `exec`, and `lease` grow a `--macaroon <b64>` flag and also honour `LLM_SECRETS_MACAROON` from the environment. When a macaroon is presented:

1. Verify the signature chain against the session's root key.
2. Verify every caveat against the current request context.
3. **Augment** the existing policy check — the macaroon does not bypass policy; both must pass. (Macaroon is a *further restriction* on what the dev's identity could already do, never an expansion.)
4. Audit the access with `event = "exec.inject.macaroon"` (or `peek.macaroon`) and the macaroon `id` in the `note` field.

### How the dev hands a macaroon to an agent

The intended pattern, in shell:

```bash
# Dev mints a macaroon scoped to one task
LLM_SECRETS_MACAROON=$(llms macaroon mint \
    --secret db_password \
    --ttl 5m \
    --agent claude-code)
export LLM_SECRETS_MACAROON

# Now spawn the agent. Anything it does via llms is gated by the macaroon.
claude
```

Or, for a one-shot exec:

```bash
llms exec --inject DB=db_password \
          --macaroon $(llms macaroon mint --secret db_password --ttl 1m) \
          -- ./run-migrations.sh
```

The agent never sees the root key. It cannot mint new macaroons. It can attenuate (via `llms macaroon mint --from-stdin <existing>` — deferred to v1.2 if not needed sooner) but not escalate.

## Consequences

### Positive

- **Fine-grained delegation.** The session represents the dev. The macaroon represents *one task on behalf of the dev*. These are now separate concepts, and the agent only ever holds the latter.
- **Stateless verification.** A macaroon can be verified with just the root key. No oracle, no daemon, no network. Aligns with the "single static binary" property from ADR 0001.
- **Composes with everything.** When vendor OIDC arrives (Anthropic et al. running OIDC issuers — see the contributor skill's "alternatives considered" section), the OIDC token becomes a *third-party caveat*. No format change needed.
- **Killswitch already exists.** `revoke-all` deleting the root key invalidates every derived macaroon in O(1). We get this for free.
- **Backwards compatible.** Macaroons are opt-in. Without `--macaroon` or `LLM_SECRETS_MACAROON`, every existing flow works exactly as it did in v1.0. Existing users see no behaviour change until they enable the feature.
- **Audit log gains structure.** Macaroon `id` in the audit log lets you correlate every access back to the specific token that authorised it. Forensics get measurably better.

### Negative

- **Wire format commitment.** Once we ship this and someone deploys it in CI, the JSON shape is real and breaking it costs version-bump pain. v1.1 marks the format as `experimental` in the docs to give us a wider escape hatch.
- **Hand-rolled crypto chain.** HMAC-SHA256 chains are well-understood, but any homemade crypto code is more risk than depending on an audited library. We mitigate by using `hmac` + `sha2` from the [RustCrypto](https://github.com/RustCrypto) project (the audited primitives) and only writing the chain logic ourselves. The chain logic is ~30 lines and is property-tested for tamper detection and escalation prevention.
- **One more file in `$LLM_SECRETS_DIR`.** `macaroon_root.key`. Already 0600. Mentioned in `status`.

### Future

- **Stateful caveats** (`one_shot`, `pid_alive`) — v1.2.
- **Third-party caveats** for chained authorization (the developer's Anthropic OIDC token as a caveat, the actual macaroon discharge protocol from §6 of the paper) — v1.x once vendor issuers are real.
- **Macaroon attenuation by the agent** (`llms macaroon attenuate --from-stdin`) — defer until we see real demand. The dev minting tightly-scoped macaroons up front should cover most cases.

## References

- Birgisson, Politz, Erlingsson, Taly, Vrable, Lentczner, *Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud*, NDSS 2014. The original paper.
- Mark S. Miller, *Robust Composition: Towards a Unified Approach to Access Control and Concurrency Control*, 2006. The capability-security ancestor.
- Tailscale's macaroon use for node auth keys — proof the pattern works at scale in a security-critical product.
- Fly.io's tokens — another production macaroon deployment with attenuation as a first-class feature.
