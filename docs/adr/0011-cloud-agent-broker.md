# ADR 0011 — Serving cloud agents: an injecting broker

- **Status**: Proposed
- **Date**: 2026-11-22
- **Builds on**: ADR 0002 (no `get`), ADR 0006/0007 (macaroons), ADR 0010 (fail-closed audit)
- **Touches**: SECURITY-MODEL.md's "there is no network surface" — this ADR proposes an *opt-in* exception and says what it costs

## Context

`llms` assumes the agent runs on the developer's machine. The store
(`~/.local/share/llm-secrets/`), the root key that verifies every macaroon, and
the audit log all live there, and verification is deliberately stateless and
local: "no oracle, no daemon, no network" (ADR 0006).

A growing share of agent work no longer happens there. Cloud agents run in a
vendor's container: Claude Code on the web, Codex cloud tasks, Cursor
background agents, the GitHub Copilot coding agent. A macaroon handed to one
of them is useless. It is a narrowed *authorisation*, not the secret, and
there is no store and no root key in the container for it to unlock.

So today a cloud agent that needs, say, a Cloudflare API token gets it in one
of these ways, none of which is `llms`:

1. **An environment variable on the cloud environment.** Plaintext, readable
   by every process in the container, printable by the agent, long-lived.
   Exactly the failure mode `llms` exists to prevent.
2. **Platform credential injection.** Anthropic's cloud environments let the
   user save a "network secret" for a host. The environment's egress proxy
   adds it as a request header (e.g. `Authorization: Bearer …`) to HTTPS
   requests to that host. The container never sees the value. This honours
   the spirit of ADR 0002, but the secret is static: no expiry, no
   attenuation beyond "this host", no audit the developer controls, and
   revocation means deleting it by hand.
3. **CI secrets** (GitHub Actions). Write-only and well-handled, but only for
   workflows, not for an interactive agent.
4. **Run the commands on the developer's machine.** Some platforms (Claude
   Code's Remote Control) let a cloud session run commands in a folder on the
   developer's computer. Then plain `llms exec` works unchanged. This needs no
   new code, but the machine must be online and the platform must offer it.

The question for this ADR: **can `llms` give a cloud agent delegated, expiring,
audited, revocable use of a secret, without ever putting the plaintext where
the agent can read it?**

## The constraint that decides the design

Any design in which the cloud container can *fetch* the plaintext over the
network is a `get` command with extra steps.

Suppose a broker exposes "present a macaroon, receive the secret" and the
`llms` client in the container injects the result into a child process, the
way `exec --inject` does locally. The agent holds the same macaroon (or the
platform injects it on every request to the broker's host). Nothing stops the
agent from calling the endpoint itself with `curl` and printing the response.
ADR 0002 ("no `get`, ever") is then enforced by convention, not architecture.

Locally this does not arise, because the root key and the store are on the
same machine as the gate, and the gate is the binary. Remotely, the gate must
sit on the far side of the network from the agent and **never return the
secret at all**. It must *use* the secret on the agent's behalf.

## Decision (proposed)

Add an optional broker, `llms serve`, that runs where the store lives (the
developer's machine, or a small server they control), and acts as an
**injecting reverse proxy** for declared upstream APIs.

### Shape

```
cloud container                         broker (llms serve)                upstream
───────────────                         ───────────────────                ────────
wrangler / curl ──HTTPS──▶  https://broker.example/u/cloudflare/…  ──HTTPS──▶ api.cloudflare.com
   (no secret)        Authorization: Macaroon <m>     verify m, check
                                                      caveats + policy,
                                                      audit, swap in
                                                      Authorization:
                                                      Bearer <real token>
```

- **Bindings** are declared in broker config (TOML, like profiles; ADR 0008).
  Each names an upstream host, the header to set, and the store key to fill
  it from:

  ```toml
  [binding.cloudflare]
  upstream = "https://api.cloudflare.com"
  header   = "Authorization"
  format   = "Bearer {secret}"
  secret   = "cloudflare_api_token"
  methods  = ["GET", "POST", "PATCH"]       # optional narrowing
  paths    = ["/client/v4/accounts/*/pages/*"]
  ```

- **The agent holds a macaroon, never the secret.** The broker verifies the
  HMAC chain against its root key, evaluates caveats, runs the policy check,
  writes the audit record (fail-closed under `LLM_SECRETS_AUDIT_STRICT`, as in
  ADR 0010), and only then forwards the request with the real header. The
  secret's plaintext exists only inside the broker process.
- **No endpoint returns a secret.** Not to the `llms` client, not to anyone.
  This is what keeps ADR 0002 architectural for remote use.
- **Off by default, separately built.** `serve` lives behind a cargo feature,
  so the default binary keeps its "no network surface" property, and an
  operator who never runs `llms serve` gains no exposure.

### New caveats

Remote use needs caveats the broker can check against facts *it* observes:

| Type | Meaning | Checked against |
|---|---|---|
| `binding_eq` / `bindings_in` | Restrict to named bindings | The binding in the request path |
| `method_in` | Restrict HTTP methods | The request method |
| `path_prefix` | Restrict upstream paths | The request path |
| `location_eq` | Token valid only at this broker | The broker's configured URL |

The existing `secret_eq` / `secrets_in` and `expires_at` carry over unchanged.

### What remote caveats cannot honestly check

In a cloud container, `repo`, `branch`, `agent` and `who` are claims the
container makes about itself. The broker cannot verify them. A remote
macaroon carrying `agent_eq = claude-code` restricts nothing an attacker who
holds the token cannot also claim. The broker **must** evaluate these caveats
against request headers marked as self-asserted and say so in the audit
record, or reject them on remote tokens. This ADR proposes **reject**: fail
closed rather than give a false sense of binding.

Real binding to a specific cloud session needs a third-party caveat
discharged by the vendor's identity token. That is DESIGN.md's "vendor OIDC"
horizon item, still blocked on vendors publishing an issuer. The broker
design is chosen so that item slots in as a caveat type later, with no format
change.

### Delivering the macaroon to the container

Two ways, in increasing strength:

1. **Environment variable** (`LLM_SECRETS_MACAROON`). Simple. The macaroon is
   readable in the container, but it is attenuated, expiring, scoped to
   bindings and methods, revocable, and useless anywhere but this broker.
2. **Platform injection of the macaroon (recommended where available).** Save
   the macaroon, not the real token, as the platform's network secret for the
   *broker's* host. The container then holds no credential material at all:
   the platform adds the macaroon on the way to the broker, and the broker
   adds the real token on the way upstream. The developer gets the platform's
   "invisible to the container" property plus everything `llms` adds on top:
   expiry, narrowing, audit, revocation, and a store they own. If the stored
   value leaks, it is an attenuated token for one broker, not the API key.

### Expiry vs. stored tokens

A five-minute macaroon cannot sit in a platform's stored-secret slot. Remote
tokens will be longer-lived (hours to days), so revocation can no longer rely
only on expiry or on the all-or-nothing `revoke-all`. This ADR adds the
first piece of state to verification:

- `llms revoke <macaroon-id>`: the broker keeps a deny-list of macaroon ids
  (append-only file, checked on every request). Revoking one token does not
  disturb the others. `revoke-all` (delete the root key) still kills
  everything in O(1).
- Every audit record carries the macaroon id, so "what did token X do" is one
  query.

## Alternatives considered

- **Remote fetch into `exec --inject`** (the broker returns the secret to an
  `llms` client in the container). Rejected: it is a network `get` the agent
  can call directly, as argued above.
- **Ship the encrypted store into the container.** Rejected: the decryption
  key would have to be there too, and then the agent can decrypt it.
- **Transparent forward proxy with TLS interception** (`HTTPS_PROXY` plus a
  broker CA trusted in the container). It works with tools that cannot change
  their API base URL, and cloud setup scripts usually run as root, so
  installing a CA is feasible. Deferred, not rejected: it widens the broker
  into a man-in-the-middle for all of the container's traffic and needs far
  more care. The reverse-proxy form covers any tool with a configurable
  endpoint first.
- **Rely on platform injection alone.** Fine for many users, and the
  cloud-agent guide should say so. But it gives no expiry, attenuation, audit
  or owned store, which is the whole point of `llms`.
- **Remote Control / run on the developer's machine.** The right answer when
  available, and it needs no code. It is not available everywhere, and it
  requires the machine to be online for the agent's whole run.

## Consequences

### Positive

- Cloud agents get the `llms` model (delegate a slice, never the secret)
  instead of falling back to plaintext environment variables.
- Composes with, rather than competes with, platform injection: the platform
  hides the macaroon, `llms` adds expiry, narrowing, audit and revocation.
- Keeps ADR 0002 architectural for remote use: no endpoint returns a secret.

### Negative

- **A network surface, for the first time.** A broker is a long-running,
  reachable service holding the store's key in memory. It needs TLS, a way to
  be reachable from vendor containers (a tunnel such as Cloudflare Tunnel or
  Tailscale Funnel when it runs on a laptop), rate limiting, and hardening
  that the CLI never needed. Mitigated by being opt-in, feature-gated, and
  answering nothing except verified-macaroon requests for declared bindings.
- **Stateful verification.** The id deny-list breaks the purely stateless
  model of ADR 0006. It is small and append-only, but it is state.
- **The agent can still act as the developer within the binding.** The broker
  hides the token, not the authority: a holder of the macaroon can make any
  request the binding's methods and paths allow. Response bodies are passed
  through, so an upstream that returns credentials (e.g. a token-minting
  endpoint) would leak them. Bindings should be narrow, and token-minting
  paths excluded.
- **Tool friction.** The reverse-proxy form needs tools that accept a custom
  API base URL. Tools that do not must wait for the deferred forward-proxy
  mode or use another route.

## Plan, if accepted

1. **Docs first, no code:** a cloud-agent section in the integration guide
   covering Remote Control (plain `llms`), platform injection, and why a
   remote fetch is not offered.
2. `llms serve` reverse-proxy mode behind a `serve` cargo feature: bindings,
   macaroon auth, the new caveats, fail-closed audit.
3. `llms revoke <id>` and the broker deny-list.
4. Third-party caveats for vendor identity tokens, once a vendor publishes an
   OIDC issuer for agent sessions.

## Open questions

- Should a broker be per-developer (on their machine, via a tunnel) or a
  small shared team service? The trust and availability trade-offs differ.
- How should the broker's root key relate to the developer's session root key
  (ADR 0007)? Same key: one killswitch. Separate key: a laptop `revoke-all`
  need not stop a server broker.
- Is a dedicated `Authorization: Macaroon` scheme right? Platform injection
  offers a fixed set of header schemes (Anthropic's form takes `Bearer` and a
  few others, not `Macaroon`), so the broker should at least accept the
  macaroon as a `Bearer` token. Leaning towards accepting both.
