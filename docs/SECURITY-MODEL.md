# Security model

What `llm-secrets` defends against, what it does not, and why it is shaped this way.

## Threat model

The actor we worry about most is **the AI coding agent itself** — Claude Code, Cursor, Copilot, Aider. The agent is running with the developer's full identity. It can read files, run commands, and exfiltrate anything it sees into an LLM context window where it becomes part of training data, transcripts, or provider logs.

We assume:

- The agent **is not malicious**, but it has no good way to know what it shouldn't read.
- The agent's outputs (stdout, stderr, command transcripts) are **persisted by a third party**.
- The developer can **type a password** but cannot reliably **remember not to**.
- The host machine's filesystem is otherwise trusted: anyone with root has already won.

We do **not** defend against:

- A compromised host (root, a malicious kernel module, a rogue init system).
- Side channels in the underlying crypto crates (`age`, `ed25519-dalek`). Report those upstream.
- Network-level attacks. There is no network surface.
- Social engineering of the developer.

## Architectural guarantees

These are properties of the **shape** of the binary, not promises about behaviour. They are verifiable by reading the source.

### G1 — There is no `get` command

The `Command` enum in `src/cli.rs` has no `Get` variant. There is no code path that decrypts a secret and prints it to stdout. The integration test `tests/cli.rs::no_get_command_exists` regression-tests this.

Plaintext leaves the binary in exactly two ways:

1. **`exec --inject`** places it in a child process's environment. The parent never writes it.
2. **`peek`** prints a *masked* preview, not the value.

See [ADR 0002](adr/0002-no-get-command.md).

### G2 — The MCP tool surface is a strict subset of the CLI

`llms mcp` exposes `list_secrets`, `peek_secret`, `audit_recent`, `status`. Nothing else. There is no MCP tool whose return value contains a plaintext secret. An LLM connected to the server cannot ask for one because no such tool exists.

See [ADR 0005](adr/0005-mcp-server.md).

### G3 — Sessions are tamper-evident

A session file (`session.json`) carries an Ed25519 signature over its claims. Editing the file by hand invalidates the signature. The private key is **dropped after signing** — no new claims can be added to a session, only verified.

This is local-only: it proves continuity within a session, not identity to a third party. v1.x can grow remote attestation on top of the same shape.

See [ADR 0004](adr/0004-session-identity.md).

### G4 — Policy is allow-list by default

A key not mentioned in `.llm-secrets-policy.yaml` is **denied**, not allowed. `deny` rules short-circuit `allow` rules. There is no implicit "allow all".

When a policy file is present, every secret read requires an active, non-expired session.

### G5 — Every read is auditable

`peek` and `exec --inject` append to `$LLM_SECRETS_DIR/audit.jsonl` whenever a session is active. The audit log records: time, event, key, who, repo, branch, agent, pid. `llms audit` reads it back.

Audit failures **do not** abort the access path — by the time we'd fail, the secret has already been used. They are logged on stderr instead. Strict-mode audit (fail closed) is planned for v1.x.

### G6 — Encryption at rest with audited primitives

The store is one age-encrypted file (X25519 key agreement + ChaCha20-Poly1305 AEAD), via the [`age`](https://crates.io/crates/age) Rust crate. The age identity lives in a separate file with mode 0600 inside a 0700 directory. Writes are atomic (write-to-`.tmp` + rename).

See [ADR 0003](adr/0003-store-layout.md).

## What still needs the developer's care

Architectural enforcement reduces the surface but does not eliminate it. The developer is still responsible for:

- **Backing up `identity.txt`.** No identity, no decryption.
- **Choosing strong values.** `llms set` does not enforce entropy.
- **Not pasting secrets into chat windows.** We cannot help with this. The whole point of the tool is to make the agent route around the human's hand here.
- **Reviewing the policy file.** A permissive policy is not the tool's fault.

## Reporting issues

See [SECURITY.md](../SECURITY.md). **Do not open public issues for security bugs.**
