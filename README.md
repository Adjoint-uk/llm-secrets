# llm-secrets

SOPS wrapper for the AI agent era - manage secrets without leaking them to LLM context.

## The Problem

When using AI coding assistants (Claude Code, Copilot, Cursor), secrets can leak into:
- Chat history and logs
- Shell command history
- LLM context windows (visible to the model)

Traditional secret management tools output full values, which get captured by LLMs.

## The Solution

`llm-secrets` provides LLM-safe secret operations:

| Command | LLM Safe? | Use Case |
|---------|-----------|----------|
| `list` | Yes | Show available secret keys (no values) |
| `peek` | Yes | View masked secret (`sk-12****cdef`) |
| `set` | Yes | Add secret via hidden input |
| `exec` | Yes | Run command with secrets injected |
| `get` | **No** | Retrieve full value (scripts only) |

## Installation

```bash
# Requires: sops, age
sudo apt install sops age  # Debian/Ubuntu
brew install sops age      # macOS

# Install llm-secrets
uv pip install llm-secrets
# or
pip install llm-secrets
```

## Quick Start

### First-Time Setup (one time only)

```bash
# 1. Install dependencies
sudo apt install sops age    # Debian/Ubuntu
# or: brew install sops age  # macOS

# 2. Generate your encryption key
mkdir -p ~/.config/sops/age
age-keygen -o ~/.config/sops/age/keys.txt

# 3. Initialize secrets file
llm-secrets init

# 4. Verify setup
llm-secrets status
```

### Daily Usage

```bash
# Add a secret (hidden input - safe)
llm-secrets set my_api_key

# List keys (safe for LLM)
llm-secrets list

# Peek at value (safe for LLM)
llm-secrets peek my_api_key
# Output: my_api_key: sk-12********cdef

# Run command with secret injected
llm-secrets exec --inject API_KEY=my_api_key -- curl -H "Authorization: $API_KEY" https://api.example.com
```

## Commands

### `llm-secrets list`

List all secret keys. Safe for LLM context.

```bash
$ llm-secrets list
┌─────────────────────────────┬───────────┐
│ Key                         │ Status    │
├─────────────────────────────┼───────────┤
│ anthropic_api_key           │ available │
│ github_token                │ available │
│ _example                    │ internal  │
└─────────────────────────────┴───────────┘
Total: 3 secrets
```

### `llm-secrets peek <key>`

View masked secret value. Safe for LLM context.

```bash
$ llm-secrets peek github_token
github_token: ghp_****************************cdef
Length: 40 chars
```

Options:
- `-c, --chars N` - Show N chars at start/end (default: 4)

### `llm-secrets set <key>`

Add or update a secret. Uses hidden input by default.

```bash
$ llm-secrets set my_secret
Setting secret: my_secret
Enter value (hidden):
Confirm value (hidden):
Set: my_secret = sk-1****5678
```

Options:
- `--value VALUE` - Set directly (NOT recommended - visible in history)
- `--from-file PATH` - Read from file
- `--delete-file` - Delete source file after reading

### `llm-secrets get <key>`

Get full secret value. **NOT safe for LLM context**.

```bash
# Only use in scripts that pipe the output
TOKEN=$(llm-secrets get github_token)
```

### `llm-secrets exec`

Run a command with secrets injected as environment variables.

```bash
# Single secret
llm-secrets exec --inject GH_TOKEN=github_token -- gh pr list

# Multiple secrets
llm-secrets exec \
  --inject AWS_ACCESS_KEY_ID=aws_key \
  --inject AWS_SECRET_ACCESS_KEY=aws_secret \
  -- aws s3 ls
```

### `llm-secrets delete <key>`

Delete a secret.

```bash
$ llm-secrets delete old_api_key
Delete: old_api_key = sk-1****5678
Type 'yes' to confirm: yes
Deleted: old_api_key
```

### `llm-secrets init`

Initialize a new secrets file.

```bash
$ llm-secrets init
Initialized: ~/.config/llm-secrets/secrets.yaml
```

### `llm-secrets status`

Show status and configuration.

```bash
$ llm-secrets status
┌──────────────┬───────────┬─────────────────────────────────────────┐
│ Component    │ Status    │ Path/Info                               │
├──────────────┼───────────┼─────────────────────────────────────────┤
│ sops         │ installed │                                         │
│ age          │ installed │                                         │
│ secrets file │ exists    │ /home/user/.config/llm-secrets/secrets  │
│ age key      │ exists    │ /home/user/.config/sops/age/keys.txt    │
└──────────────┴───────────┴─────────────────────────────────────────┘
Secrets: 5 keys
```

## Configuration

### Environment Variables

| Variable | Description |
|----------|-------------|
| `LLM_SECRETS_FILE` | Override default secrets file path |
| `SOPS_AGE_KEY_FILE` | Override age key location |

### Default Paths

- Secrets: `~/.config/llm-secrets/secrets.yaml`
- Age key: `~/.config/sops/age/keys.txt`

## Age Key Setup

If you need to set up encryption keys on a new machine:

```bash
# Create key directory
mkdir -p ~/.config/sops/age

# Generate new key pair
age-keygen -o ~/.config/sops/age/keys.txt

# View your public key (safe to share/backup)
age-keygen -y ~/.config/sops/age/keys.txt
```

**Important:** Keep your private key (`keys.txt`) secure. Anyone with this key can decrypt your secrets.

## Security Model

- Secrets encrypted at rest using SOPS + age
- `peek` only shows first/last N characters
- `set` uses hidden input (not in shell history)
- `exec` injects secrets without exposing them
- `get` is the only command that outputs full values

## Python API

```python
from llm_secrets import secrets

# List keys (safe)
keys = secrets.list_keys()

# Peek at value (safe)
masked = secrets.peek_secret("api_key")
print(masked)  # sk-12********cdef

# Get full value (unsafe - use carefully)
value = secrets.get_secret("api_key")

# Set a secret
secrets.set_secret("new_key", "secret_value")

# Delete a secret
secrets.delete_secret("old_key")
```

## Use with Claude Code

When working with AI assistants:

```bash
# Safe commands (LLM can see output):
llm-secrets list
llm-secrets peek my_key
llm-secrets status

# Unsafe commands (don't run in chat):
llm-secrets get my_key  # Full secret exposed!
```

## License

MIT
