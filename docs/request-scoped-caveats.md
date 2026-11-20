# Request-scoped caveats and the credential proxy

Status: phase 1 (caveats) implemented; phase 2 (proxy) not yet.

## Problem

Today a macaroon scopes *who* may release a secret (secret, repo, branch, agent, user, expiry). Once released, the
agent holds the secret and can use it for anything. Two gaps follow:

1. **Per-tool / per-parameter limits.** "May create a *private* repo named `proj-*`" cannot be expressed.
2. **The agent still holds the secret.** A prompt-injected agent can leak or reuse it (issue #46).

## Phase 1: request-scoped caveats (this change)

New caveats, checked against the outbound HTTP request a proxy is about to forward:

| Caveat | Meaning |
|---|---|
| `host_in` | Host is one of the list (case-insensitive, exact, no port) |
| `method_in` | Method is one of the list |
| `path_glob` | Path matches; `*` stays within a segment, a `**` segment matches zero or more segments, trailing slash significant |
| `body_eq` | JSON body field (RFC 6901 pointer) equals a value |
| `body_glob` | JSON body string field matches a glob |
| `body_keys_in` | Body is an object with only these top-level keys (blocks smuggled extra fields) |

Properties:

- **Attenuation only.** They are ordinary caveats in the HMAC chain, so they can be added by delegation and never removed.
- **Fail closed.** Only a proxy sets `Context::request`. `exec`, leases and MCP have none, so a token carrying any of
  these caveats cannot release a secret except through the proxy.
- **Strict normalisation.** `RequestCtx::new` lowercases host, uppercases method, drops query and fragment, and refuses
  anything ambiguous: empty host, port, userinfo, `//`, `.`/`..` segments, encoded `.`, `/`, `\`, NUL, backslashes.
- **No value leaks.** Denial messages name the pointer, never the body value.

Not included yet: usage counts (`max_uses`) need persistent state; deferred.

## Threat model

Defends against: an agent (or injected instructions) using a delegated token for a different host, method, path or
payload than was granted; widening a token by dropping caveats; smuggling fields or traversal paths past a check.

Does not defend against: a compromised proxy host; an allowed endpoint that is itself dangerous (scope narrowly);
header-based or non-JSON bodies (rejected by body caveats rather than guessed at); the holder of a plain,
non-request-scoped token.

## Phase 2: `llms proxy` (needs decisions)

The proxy holds the secrets and the root key, accepts requests from the agent carrying only a macaroon, verifies it with
the request context, injects the real credential, forwards, and logs to `llms audit`. The agent never sees the secret.

Open decisions:

- **Route mode** (agent calls `http://localhost:PORT/<service>/...`, simplest, no TLS interception) versus **MITM**
  (works with unmodified tools, but needs a local CA and is a larger attack surface). Recommendation: route mode first.
- New dependencies (HTTP server and client, TLS). Keep minimal; prefer a small blocking server plus `ureq`.
- Credential mapping: which secret and which header (`Authorization: Bearer`, basic, custom) per upstream host.

## Phase 3: hub integration

The hub validates a worker's request (see the hub-request flow), maps the validated parameters to caveats
(`host_in`, `path_glob`, `body_eq` on `/private`, `body_keys_in`), mints a short-lived attenuated token, and the
proxy performs the call. Tier A actions then no longer require the hub to hold ambient rights for the whole action.
