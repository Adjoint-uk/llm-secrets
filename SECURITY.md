# Security Policy

`llm-secrets` is a security tool. We take vulnerability reports seriously.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Email **security@adjoint.uk** with:

- A description of the issue
- Steps to reproduce (or a proof of concept)
- The affected version (`llms --version`)
- Your assessment of impact

You should receive an acknowledgement within 72 hours. We will work with you to confirm, fix, and disclose.

## Scope

In scope:

- Anything that causes a secret to be exposed to the LLM context, stdout, logs, or an unauthorised process
- Bypasses of the policy engine (once shipped in v0.3)
- Bypasses of lease expiry or the killswitch (once shipped in v0.4)
- Cryptographic flaws in the on-disk format
- Memory hygiene issues (plaintext lingering after use)

Out of scope:

- Issues that require root on the user's machine (game over already)
- Side-channel attacks against the underlying `age` / `ed25519-dalek` crates (report upstream)
- Social engineering / phishing of users

## Supported Versions

Pre-1.0. We patch the latest released version only.
