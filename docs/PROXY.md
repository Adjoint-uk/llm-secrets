# `llms proxy` — keep the credential out of the agent

The agent holds a macaroon. The proxy holds the secret. For each request the
proxy checks the macaroon against the request it is about to send, swaps in the
real credential, forwards over HTTPS, and audits. Design and limits:
[ADR 0011](adr/0011-credential-proxy.md).

## 1. Describe your services

`~/.config/llm-secrets/proxy.toml` (or `$LLM_SECRETS_CONFIG_DIR/proxy.toml`, or
`--config PATH`):

```toml
# optional global limits (defaults shown)
max_body_bytes       = 1048576   # request bodies larger than this get 413
max_response_bytes   = 16777216
connect_timeout_secs = 5
timeout_secs         = 30

[services.github]
upstream = "https://api.github.com"
secret   = "github_token"        # a name in your llms store
inject   = "bearer"              # Authorization: Bearer <secret>

[services.jira]
upstream = "https://example.atlassian.net/rest/api/3"   # a path prefix is allowed
secret   = "jira_basic"          # stored as user:token
inject   = "basic"               # Authorization: Basic base64(<secret>)

[services.search]
upstream = "https://search.example.com"
secret   = "search_key"
inject   = "header"
header   = "X-Api-Key"
```

Upstreams must be `https://`, with no userinfo, query or fragment. The host is
fixed here; nothing in a request can change it.

```bash
llms proxy check                 # validate the file and that every secret exists
llms proxy check --service github
```

## 2. Run it

```bash
llms proxy serve                 # 127.0.0.1:8787
llms proxy serve --bind 127.0.0.1:9000
```

It prints `listening on 127.0.0.1:PORT (services: ...)` and runs until stopped.
Start it from the repo and branch you minted tokens in (see *Limits*).

## 3. Mint a narrow token, hand it to the agent

```bash
M=$(llms macaroon mint --secret github_token --ttl 10m \
      --method GET --path '/repos/adjoint-uk/*')

curl -H "Authorization: Bearer $M" \
     http://127.0.0.1:8787/github/repos/adjoint-uk/llm-secrets
```

`<service>` is the first path segment; the rest is sent upstream. `X-Llms-Token:
<macaroon>` is accepted instead of `Authorization` for clients that need that
header for something else.

Request caveats on `macaroon mint` (only the proxy can satisfy them):

| Flag | Caveat | Example |
|---|---|---|
| `--host H` | `host_in` | `--host api.github.com` |
| `--method M` | `method_in` | `--method GET --method HEAD` |
| `--path GLOB` | `path_glob` (`*` within a segment, `**` across) | `--path '/repos/*/issues'` |
| `--body-eq /ptr=JSON` | `body_eq` | `--body-eq /private=true` |
| `--body-glob /ptr=GLOB` | `body_glob` | `--body-glob '/name=proj-*'` |
| `--body-key K` | `body_keys_in` | `--body-key name --body-key private` |

The path a caveat sees is the path sent upstream, including any prefix from the
service's `upstream` URL. The token must name the service's secret (`--secret`).

## Responses you will see

| Status | Meaning |
|---|---|
| upstream's | The request was allowed. Redirects are returned as-is, never followed. |
| 400 | Malformed target, ambiguous path, or JSON that does not parse strictly |
| 403 | No/invalid/expired/tampered token, wrong secret, or a caveat failed |
| 404 | Unknown service |
| 405 | Method not forwarded (anything but GET HEAD POST PUT PATCH DELETE OPTIONS) |
| 413 | Body over `max_body_bytes` |
| 502 | Upstream unreachable, too slow, or response too large |

Bodies are generic on purpose. To find out *why* a request was refused, ask the
person running the proxy: `llms audit --last 20` shows `reason=` for each
`proxy.request` event (for example `caveat:method_in`).

## Limits worth knowing

- **Loopback only.** `--allow-non-loopback` exists and warns; there is no TLS
  and no authentication other than the macaroon.
- **Environment caveats follow the proxy**, not the caller. `repo`, `branch`,
  `agent` and `who` caveats are checked against the proxy's own environment.
- **The query string and non-credential headers are not covered** by caveats.
  Scope tokens to endpoints that are safe whatever the query says.
- **JSON bodies only.** Body caveats need `Content-Type: application/json`
  (or `+json`); any other body makes a body caveat fail. Duplicate keys are
  refused.
- **Echo stripping is best effort:** response headers containing the credential
  are dropped; bodies are not inspected.
- **Development only:** `--allow-loopback-http` accepts `http://127.0.0.1`
  upstreams, sending the credential in clear text to loopback.
