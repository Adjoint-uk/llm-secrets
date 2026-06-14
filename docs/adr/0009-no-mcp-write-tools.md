# ADR 0009 — No secret-mutating MCP tools (MCP stays read/exec-only)

- **Status**: Accepted
- **Date**: 2026-06-13
- **Builds on**: ADR 0002 (no `get` command), ADR 0005 (MCP server)
- **Implemented in**: n/a — this ADR decides *not* to build a feature.

## Context

The MCP server (ADR 0005) is the agent-facing surface of `llms`. By design it
exposes only tools that never return plaintext on a channel an agent could
exfiltrate (ADR 0002): inspect/list, and `exec`-style injection into a child
process. There is deliberately no way for an agent to *read* a secret value.

The question (#18) is the mirror image: should the MCP surface gain *write*
tools — `set` and `delete` — gated by an `mcp.write` policy field, so an agent
could provision or remove secrets?

### What we considered

- **Expose `set`/`delete` over MCP, gated by `mcp.write` (default deny).** Adds a
  policy knob; agents with the grant could create and delete store entries.
- **Expose them freely.** Rejected outright — incompatible with the threat model.

## Decision

**Do not expose secret-mutating tools over MCP.** `set` and `delete` remain
**CLI-only**, i.e. human-driven. The MCP surface stays read/exec-only.

Rationale:

- **Blast radius vs. benefit.** `delete` is destructive and `set` can silently
  overwrite a live credential. Handing those to a confused or compromised agent
  is high-risk; the benefit (an agent provisioning its own secret) is niche.
- **Roles.** Provisioning a secret is a human onboarding step. Agents *consume*
  secrets; they do not manage the store. Keeping that boundary keeps the
  agent-facing surface minimal and auditable.
- **No consumer.** Nothing concrete needs this today. We do not add speculative
  attack surface to a security tool.

**If a real need arises**, the shape is specified in advance so the next ADR can
move fast: a `mcp.write` policy field **defaulting to deny**; `set` and `delete`
as *separate* grants (deleting is strictly more dangerous than setting); every
write still audited; and a superseding ADR recording the consumer that justified
it. None of this is built now.

## Consequences

- The MCP surface remains small and read/exec-only — easy to reason about.
- Agents cannot mutate the store; an over-permissioned or compromised agent
  cannot delete or overwrite credentials.
- Humans use the CLI (`llms set` / `llms delete`) for all store mutation.
- **Revisit trigger:** a concrete automation that must provision secrets with no
  human in the loop. Until then, this stays Accepted.
