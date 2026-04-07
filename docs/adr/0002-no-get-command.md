# ADR 0002 — No `get` command

- **Status**: Accepted
- **Date**: 2026-03-22
- **Closes**: #2

## Context

Existing secret managers (`sops`, `pass`, `doppler`, `vault`) all expose some form of `get <key>` that prints a plaintext secret to stdout. In an AI agent context this is fatal: the moment a secret hits stdout it lands in the LLM's context window and is persisted to logs, transcripts, and provider backends.

Telling the agent "don't run `get`" is not security. It is a request.

## Decision

`llm-secrets` does not have a `get` command, and never will. Plaintext leaves the binary only via:

- `exec --inject ENV=key -- cmd` — secrets are placed in the *child process's* environment, never in this process's stdout.
- `peek <key>` — masked preview, deliberately lossy.

This is enforced architecturally:

- The `Command` enum in `src/cli.rs` has no `Get` variant. There is no code path that prints a decrypted value to stdout.
- An integration test (`tests/cli.rs::no_get_command_exists`) asserts that `llms get <anything>` exits non-zero, so the absence is regression-tested.
- `llms --help` is asserted not to mention `get`.

## Consequences

### Positive

- The guarantee is verifiable by reading 50 lines of source. Users do not have to trust the implementation; they can audit the absence.
- Removes a class of "I just need to copy this once" footguns.
- Forces all callers down the `exec`/`inject` path, which is the path we can actually defend with policy and leases.

### Negative

- One-off shell use is slightly less ergonomic. A human who needs to look at a secret can `llms exec --inject X=key -- sh -c 'echo $X'` — clunky on purpose.
- We may field repeated "please add a `get` command" issues. Policy: close as `wontfix` and link this ADR.
