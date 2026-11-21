# Request-scoped caveats and the credential proxy

Status: phase 1 (caveats) and phase 2 (route-mode proxy) implemented.

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

## Phase 2: `llms proxy` (route mode)

`llms proxy serve [--bind ADDR:PORT] [--config PATH]` (default `127.0.0.1:8787`). The agent calls
`http://127.0.0.1:PORT/<service>/<upstream path>` with `Authorization: Bearer <macaroon>` (or `X-Llms-Token`).
No TLS interception, no local CA.

Services live in `services.toml` in the llms config dir (next to `profiles.toml`):

```toml
max_body_bytes = 1048576      # optional, default 1 MiB
connect_timeout_secs = 5      # optional
timeout_secs = 30             # optional, total

[services.github]
upstream = "https://api.github.com"   # https only; the host is fixed here, never taken from the request
secret   = "github_token"
inject   = "bearer"                   # bearer | basic (secret is "user:pass") | header
# header = "X-Api-Key"                # required with inject = "header"
```

Per request the proxy: validates the target (400 on anything `RequestCtx::new` refuses), requires a macaroon that
carries `secret_eq`/`secrets_in`, caps and parses the body (JSON only for a JSON `Content-Type`, duplicate keys
refused; otherwise body caveats see no body and fail closed), calls `Macaroon::verify` with a fresh `Context` whose
`request` is the real request, injects the credential, forwards without following redirects, and audits. Every
denial is a generic 403 (reason in the audit log only). `llms proxy check --service S` validates config and that the
secret exists. `llms macaroon mint` gained `--host/--method/--path-glob/--body-eq/--body-glob/--body-keys` to mint
request-scoped tokens.

Notes and limits:

- `path_glob` is matched against the agent-supplied path (after `/<service>`), not the configured base path.
- `repo_eq`, `branch_eq`, `agent_eq`, `who_eq` are evaluated against the proxy process's environment
  (`Context::current` per request), as for every other llms entry point.
- Revocation: the proxy reads the root key on every request, so `revoke-all` and a new `session-start` kill tokens at once.
- Audit entries (`proxy.allow` / `proxy.deny`) record service, method, upstream host, path (no query), decision and
  the failing caveat name. Allows are written before forwarding, so `LLM_SECRETS_AUDIT_STRICT` fails closed.
- Response headers that visibly echo the injected credential are dropped (best effort: encoded echoes and echoes in the
  body are not detected). Responses are buffered (32 MiB cap).
- Non-loopback binds need `--allow-non-loopback` and print a warning. Plain HTTP only.

## Phase 3: hub integration

The hub validates a worker's request (see the hub-request flow), maps the validated parameters to caveats
(`host_in`, `path_glob`, `body_eq` on `/private`, `body_keys_in`), mints a short-lived attenuated token, and the
proxy performs the call. Tier A actions then no longer require the hub to hold ambient rights for the whole action.
