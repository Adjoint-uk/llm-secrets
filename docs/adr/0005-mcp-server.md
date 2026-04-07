# ADR 0005 — MCP server mode

- **Status**: Accepted
- **Date**: 2026-04-07
- **Closes**: #10

## Context

AI coding agents (Claude Code, Cursor, Continue) speak the [Model Context Protocol](https://modelcontextprotocol.io/) — JSON-RPC 2.0 over stdio. Exposing `llm-secrets` as an MCP server lets an agent call our **safe** primitives (`list`, `peek`, `lease`, `exec`) without ever seeing a `get`-shaped tool.

This is the natural endpoint of the architectural-enforcement principle. The agent's tool surface is the same surface a human gets — we cannot accidentally expose more than that.

## Decision

`llms mcp` runs a minimal MCP server on stdio, hand-rolled in ~150 lines. We do not pull in an MCP SDK. The wire protocol is small, our tool surface is small, and a dependency on a fast-moving third-party crate is not worth the convenience.

Tools exposed:

| MCP tool | Wraps | Notes |
|---|---|---|
| `list_secrets` | `cmd_list` | Returns key names only — never values. |
| `peek_secret` | `cmd_peek` | Returns the *masked* preview, not the plaintext. |
| `lease_secret` | `cmd_lease` | Records a lease. The agent can prove its policy compliance, not extract the secret. |
| `audit_recent` | `cmd_audit` | Read-only inspection of the audit log. |
| `status` | `cmd_status` | Store health. |

Not exposed:

- `set` / `delete` — write operations stay human-only for v1.0. v1.x can revisit with explicit policy gating.
- `exec` — the child-process model does not map cleanly to MCP. The agent should call its own host tool to spawn processes; it can call `lease_secret` first to get audited access.
- Anything that returns a plaintext value. **There is no tool that returns a secret to the model.**

## Consequences

### Positive

- Architectural enforcement extends to the LLM tool layer. The model literally cannot ask for plaintext because no such tool exists.
- Hand-rolled implementation keeps the dependency footprint at zero new crates.
- The MCP server is just another command — it shares the same store, session, policy, lease, and audit code as the CLI. No drift possible.

### Negative

- Hand-rolled JSON-RPC means we own the wire format. The MCP spec is small and stable, but we will need to track changes manually.
- Some legitimate agent flows (auto-rotate a key) need write access. These will need their own ADR before being added.
