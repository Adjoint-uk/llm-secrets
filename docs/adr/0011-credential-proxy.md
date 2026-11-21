# ADR 0011 — Credential proxy: route mode, macaroon as placeholder

- **Status**: Accepted
- **Date**: 2026-11-21
- **Builds on**: ADR 0006/0007 (macaroons), request-scoped caveats (#47)
- **Implemented in**: #48

## Context

A macaroon limits who may *release* a secret. Once released (`exec --inject`,
leases) the agent holds the plaintext and can leak or reuse it, and a
prompt-injected agent can do the same (#46). Request-scoped caveats (#47) can
describe what an outbound HTTP request may look like, but only something that
sees the request can enforce them.

## Decision

`llms proxy` holds the secrets and the root key. The agent holds only a
macaroon and never a credential.

1. **Route mode.** The agent calls `http://127.0.0.1:PORT/<service>/<upstream
   path>`. No TLS interception, no local CA. MITM is out of scope: it works with
   unmodified tools but needs a trusted CA and is a much larger attack surface.
2. **The macaroon is the placeholder.** The agent sends it as
   `Authorization: Bearer <macaroon>` (or `X-Llms-Token`); the proxy strips it
   and injects the real credential. There is no placeholder table to keep in
   sync, and a tool configured with "an API key" works unchanged.
3. **The upstream is config, not input.** A services file maps `<service>` to
   an https base URL, a secret name and an injection style (`bearer`, `basic`,
   or a named header). The host the request is verified against is the host it
   is sent to, and the agent cannot influence it.
4. **Verify against what is actually sent.** `RequestCtx::new(host, method,
   path, body)` is built from the configured host and the validated path (service
   prefix stripped, configured prefix added). `Macaroon::verify` runs with
   `Context.request = Some(..)`. The token must additionally name the service's
   secret in a `secret_eq`/`secrets_in` caveat, so a bare session macaroon is not
   a blanket key.
5. **Fail closed, say nothing.** Any error gives a generic response and no
   upstream call; the reason (a short code, or the failing caveat's *name*) goes
   to the audit log only.
6. **Loopback only.** Binding anything else needs `--allow-non-loopback` and
   prints a warning. There is no TLS server and no authentication beyond the
   macaroon.

## Consequences and limits

- **Environment caveats are the proxy's.** `repo`, `branch`, `agent` and `who`
  are evaluated against the proxy process's environment (computed once at
  startup), not the caller's: the proxy cannot see which agent is calling.
  Start it from the repo and branch you minted in. An `agent` caveat will only
  pass if the proxy itself runs under that agent. Scope proxy tokens with
  `secret`, expiry and the request caveats.
- **Not covered:** the query string, headers other than the credential, and
  response bodies. A token is only as narrow as the endpoint it allows; an
  upstream that reflects the credential into a body defeats the proxy.
  Response *headers* that echo the credential (8+ characters) are dropped as a
  best effort.
- **Ambiguity is refused, not interpreted:** `..`, encoded `/` `.` `\` NUL,
  `//`, fragments, absolute-form targets, malformed percent escapes, duplicate
  JSON keys, method-override headers (`X-HTTP-Method-Override` and friends),
  `Host`/`X-Forwarded-*` overrides.
- **Secrets are decrypted per request**: the one needed value is copied into a
  zeroising buffer and the decrypted store is dropped straight away, so
  `revoke-all`, `revoke-all --rotate` and `llms set` take effect without a
  restart and nothing long-lived holds plaintext.
- **Audit** (`proxy.request` events) records service, method, upstream host,
  path (no query), decision and reason. Never tokens, credentials, headers or
  bodies. The allow entry is written *before* forwarding, so with
  `LLM_SECRETS_AUDIT_STRICT=1` (ADR 0010) an unrecordable request is not sent.
- **Redirects are returned as-is** and never followed, so a 3xx cannot carry
  the credential to another host.

## Dependencies

`ureq` 2 (blocking client, rustls; default features off, so no gzip decoding
and bodies are forwarded byte-for-byte) and `tiny_http` 0.12 (blocking server).
Nothing else was added.
