"""Configuration for llm-secrets."""

import os
from pathlib import Path


def get_config_dir() -> Path:
    """Get config directory following XDG spec."""
    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config:
        base = Path(xdg_config)
    else:
        base = Path.home() / ".config"
    return base / "llm-secrets"


def get_default_secrets_file() -> Path:
    """Get default secrets file path."""
    # Check environment variable first
    env_file = os.environ.get("LLM_SECRETS_FILE")
    if env_file:
        return Path(env_file).expanduser()

    # Default to XDG config dir
    return get_config_dir() / "secrets.yaml"


def get_age_key_file() -> Path:
    """Get age key file path."""
    env_key = os.environ.get("SOPS_AGE_KEY_FILE")
    if env_key:
        return Path(env_key).expanduser()

    # Default locations
    for path in [
        Path.home() / ".config" / "sops" / "age" / "keys.txt",
        Path.home() / ".sops" / "age" / "keys.txt",
    ]:
        if path.exists():
            return path

    return Path.home() / ".config" / "sops" / "age" / "keys.txt"


# Constants
CONFIG_DIR = get_config_dir()
DEFAULT_SECRETS_FILE = get_default_secrets_file()
AGE_KEY_FILE = get_age_key_file()
