# Integrating a tool with llm-secrets

This guide explains how to make any CLI tool consume secrets from `llms` cleanly. It covers the principle, the three integration patterns, a fully worked example (iba-connect), and the common pitfalls.

## The principle

A tool's input mechanism is the tool's business. Tools read configuration from wherever they choose: environment variables, `~/.netrc`, `.env` files, `~/.config/<tool>/config.toml`, command-line flags, stdin, a unix socket. That's the tool's interface to the world, and a good tool offers several so users can pick what fits.

**A secret manager's job is to populate one or more of those input mechanisms securely.** llms-v2 today populates *one*: the process environment, via `llms exec -i ENV_VAR=secret_key -- cmd`. That covers ~80% of modern CLIs (anything 12-factor, anything that reads from `os.environ`, anything that takes credentials via env vars). The remaining 20% — tools that only read from on-disk files — needs a different approach today, and is the motivation for the v3.0 file-based delivery work.

The integration question for any tool is therefore:

> **Does this tool read its credentials from environment variables?**

If yes → trivial. If no → wrapper-with-temp-file (today) or wait for v3.0 (`$CREDENTIALS_DIRECTORY`-style file delivery).

## The three patterns

### Pattern 1: Tool reads env vars (the easy case)

The tool already calls `os.environ.get('FOO_TOKEN')` (or the equivalent in its language). All you need is a wrapper script in `~/.local/bin/` that shadows the real binary:

```bash
#!/usr/bin/env bash
# ~/.local/bin/mytool — wrapper that injects secrets via llms-secrets
set -e
exec llms exec \
  -i FOO_TOKEN=foo_api_token \
  -i FOO_USER=foo_username \
  -- /real/path/to/mytool "$@"
```

Make it executable (`chmod +x`), make sure `~/.local/bin` is on `$PATH` *before* the directory containing the real binary, and you're done. The user runs `mytool` as normal; the wrapper transparently injects the secrets.

**Where to find the "real" path:** if the tool is installed via mise, prefer `~/.local/share/mise/shims/<tool>` — it's version-stable across language upgrades. Otherwise use `which <tool>` from a shell where your wrapper *isn't* on `$PATH`.

This is the pattern you should reach for first. It's 5 minutes of work and gets you full decoupling.

### Pattern 2: Tool reads a file (the harder case, today)

The tool only reads credentials from `~/.netrc`, `~/.aws/credentials`, a `kubeconfig`, an SSH key file, etc. Three sub-options:

**(a) If the tool accepts an alternate file path via env var or flag** — most tools do. AWS honours `AWS_SHARED_CREDENTIALS_FILE`, curl honours `--netrc-file`, kubectl honours `KUBECONFIG`. The wrapper writes a temp file from llms secrets, sets the env var, runs the tool, deletes the temp file:

```bash
#!/usr/bin/env bash
# Wrapper for a tool that reads ~/.aws/credentials
set -e
TMPCREDS=$(mktemp)
trap 'rm -f "$TMPCREDS"' EXIT
llms exec -i AWS_KEY=aws_access_key_id -i AWS_SECRET=aws_secret_access_key -- \
  bash -c 'printf "[default]\naws_access_key_id=%s\naws_secret_access_key=%s\n" "$AWS_KEY" "$AWS_SECRET"' \
  > "$TMPCREDS"
AWS_SHARED_CREDENTIALS_FILE="$TMPCREDS" exec /real/path/to/awstool "$@"
```

Caveat: the secret transits the filesystem briefly (in `/tmp`, owned by you, removed on exit). For most tools this is fine. For high-sensitivity, wait for v3.0.

**(b) If the tool only reads from a fixed path with no override** — you have to either modify the tool, write to that path before invocation and clean up after, or live with it. Modifying the tool is usually the right call: add a "read from `$FOO_TOKEN` env var if set, else fall back to file" branch upstream.

**(c) Wait for v3.0.** llms v3.0 will materialise secrets to a tmpfs directory (`$CREDENTIALS_DIRECTORY/<key>`, the systemd `LoadCredential=` model), so file-reading tools can read from a path that never touches normal filesystems and is automatically scrubbed on process exit. This is the right long-term answer for file-reading consumers; until then, pattern (a) is the workaround.

### Pattern 3: Tool talks to its own secret backend (don't double-wrap)

Some tools (Vault clients, AWS SDKs talking to IMDS, GCP tools talking to the metadata server, anything OIDC-federated) fetch their own credentials from a backend you don't control. **Don't wrap these with llms.** They have their own identity story, and adding llms in front would be redundant and potentially confusing. Let them do their thing.

The exception: if you're using such a tool *with credentials that came from a manual setup step* (e.g., a long-lived AWS access key stored locally), pattern 2 applies — wrap the access key delivery, let the tool do everything else natively.

## Worked example: iba-connect

`iba-connect` is a Python CLI for connecting to IBA proton therapy sites. It needs Active Directory credentials to authenticate against site firewalls. We integrated it with llm-secrets in two passes:

**Before integration:** `firewall.py` had 73 lines of credential lookup spanning four backends — env vars, the old `llms get` command, a legacy `~/.claude/skills/secrets-manager/scripts/get-secret.py`, and `~/.netrc`. Every backend was hardcoded into the tool. Tightly coupled.

**Wrong first attempt:** when llms v2 broke the `llms get` path, we patched `firewall.py` to shell out to `llms exec -i ... -- printenv` from inside Python. This worked but kept iba-connect coupled to llms by name.

**Right second attempt (the current state):**

1. **`firewall.py` simplified to 8 lines** that read two env vars and raise a clear error if missing. Zero references to `llms`, `secrets`, `sops`, `netrc`, or any specific secret manager. The function looks like this:

   ```python
   def _get_credentials() -> Tuple[str, str]:
       username = os.environ.get('IBA_AD_USERNAME')
       password = os.environ.get('IBA_AD_PASSWORD')
       if username and password:
           return username, password
       raise ValueError(
           "IBA_AD_USERNAME / IBA_AD_PASSWORD not set in environment. "
           "Launch via the iba-connect wrapper, or set them directly, "
           "or run under `llms exec -i ...`."
       )
   ```

2. **Wrapper script at `~/.local/bin/iba-connect`** (7 lines of bash):

   ```bash
   #!/usr/bin/env bash
   set -e
   exec llms exec \
     -i IBA_AD_USERNAME=iba_ad_username \
     -i IBA_AD_PASSWORD=iba_ad_password \
     -- /home/galactus/.local/share/mise/shims/iba-connect "$@"
   ```

3. **PATH ordering** ensures `~/.local/bin/iba-connect` shadows the mise shim when called as `iba-connect`. The wrapper invokes the mise shim by absolute path so it still finds the real binary.

4. **One-time setup per shell session:** `llms session-start --ttl 8h`.

After this, `iba-connect auth F18` from any shell (with an active session) just works. The Python knows nothing about secret managers. The wrapper is the *only* place that names `iba_ad_username` / `iba_ad_password` and shells out to `llms`. Swapping secret managers later means editing this one bash file — no Python changes.

**Why this is the right shape:**

- The tool exposes one interface (env vars). Any launcher can populate them: the wrapper, a manual `export`, a test fixture, a CI runner, or a future v2.1 `llms exec --profile iba -- iba-connect`. **One interface, many launchers.**
- The wrapper is replaceable. If you stop using llms entirely tomorrow, replace the wrapper with a different one — the Python doesn't care.
- The wrapper is the seam between "the secret manager" and "the tool." Cleanly separated.

## Common pitfalls

### "I called `llms exec` from inside Python" — coupling smell

If a tool's source code mentions `llms` by name, you've coupled the tool to a specific secret manager. The tool now has to be rebuilt or re-released every time llms changes its CLI. Move the `llms` reference *out* of the tool and into a wrapper. The tool reads env vars; the wrapper invokes llms. Always.

### "PATH ordering is wrong, the wrapper isn't being called"

Check `which mytool`. If it returns the real binary's path, your wrapper isn't earlier on `$PATH`. Move `~/.local/bin` (or wherever you put the wrapper) earlier in the PATH ordering, or use a different wrapper name. Run `hash -r` after creating the wrapper if the shell is caching the old resolution.

### "The wrapper shells out to itself in an infinite loop"

The wrapper resolves `/some/path/iba-connect`, but inside the wrapper you write `exec iba-connect "$@"` instead of the absolute path — and `iba-connect` resolves back to the wrapper. Always invoke the real binary by absolute path inside the wrapper.

### "`llms exec` errors with no active session every time"

You forgot `llms session-start`. Sessions are per-shell, default TTL 1h. Add `llms session-start --ttl 8h` to your shell startup if you want it to be ambient, or run it manually once per workday. *(v2.1 will improve this error message to plain English.)*

### "I'm tempted to put the secret directly in the wrapper as a literal"

Don't. The whole point is that secrets live in the encrypted store, the wrapper only references them by *key name*. A literal in a bash script ends up in shell history, dotfile backups, screenshots, screen-share recordings.

### "The tool reads from `.env` and I want to use llms"

`.env` files are just env vars in disguise — most loaders (`python-dotenv`, `dotenv-cli`, etc.) read them at startup and inject into `os.environ`. So pattern 1 applies: use `llms exec`, the env vars get populated, and the tool's `.env` loader either finds them already set (and skips them) or there's no `.env` file at all. Don't write a `.env` file from llms — that's pattern 2 territory and worse than just using env vars directly.

### "I want the wrapper to work for tools my AI agents call too"

It will. Wrappers in `~/.local/bin/` are PATH-resolved by everything that respects `$PATH`, including subprocesses spawned by Claude Code, scripts, cron jobs, and other tools. As long as the agent's shell inherits the user's PATH and the user has an active llms session, the wrapper works transparently. If you want to be explicit, the agent can `llms session-start` itself before calling the wrapped tool.

## Coming in v2.1

The wrapper-script pattern accumulates boilerplate when you have many tools needing overlapping secret bundles. v2.1 introduces **profiles** — named bundles defined in `~/.config/llm-secrets/profiles.toml`. The iba-connect wrapper above will become:

```bash
#!/usr/bin/env bash
set -e
exec llms exec --profile iba -- /home/galactus/.local/share/mise/shims/iba-connect "$@"
```

…with the env mapping (`IBA_AD_USERNAME=iba_ad_username`, etc.) moved into a one-time `[iba]` section in `profiles.toml`. New tools that need the same secret bundle just reuse `--profile iba`, no per-tool boilerplate. See [ADR 0008](adr/0008-toml-profiles.md) for the design.

The integration *principle* doesn't change — your tool still reads env vars, the wrapper still injects them, llms is still the populator. v2.1 just makes the wrapper's contents shorter.

## TL;DR

1. Make your tool read credentials from env vars. Nothing else.
2. Put a 5-line bash wrapper in `~/.local/bin/` that calls `llms exec -i VAR=key -- /real/path/to/tool "$@"`.
3. Make sure `~/.local/bin` is early on `$PATH`.
4. Run `llms session-start --ttl 8h` once per day.
5. Done. Your tool is decoupled, your secrets stay in the encrypted store, and the migration to v2.1 profiles will be a 1-line edit when the time comes.
