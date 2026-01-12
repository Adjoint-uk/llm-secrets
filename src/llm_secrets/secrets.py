"""Core secrets management functionality."""

import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

import yaml

from .config import DEFAULT_SECRETS_FILE, AGE_KEY_FILE, CONFIG_DIR


class SecretsError(Exception):
    """Base exception for secrets errors."""
    pass


class SecretsNotFoundError(SecretsError):
    """Secrets file not found."""
    pass


class KeyNotFoundError(SecretsError):
    """Secret key not found."""
    pass


class SOPSError(SecretsError):
    """SOPS command failed."""
    pass


def mask_value(value: str, peek_chars: int = 4) -> str:
    """
    Mask a secret value, showing only first and last N characters.

    This is the core LLM-safety feature - secrets are never fully exposed
    to the LLM context, but users can still verify they have the right secret.
    """
    if not value:
        return "(empty)"

    if len(value) <= peek_chars * 2:
        return "*" * len(value)

    first = value[:peek_chars]
    last = value[-peek_chars:]
    hidden_len = len(value) - (peek_chars * 2)
    return f"{first}{'*' * min(hidden_len, 8)}{last}"


def check_sops_installed() -> bool:
    """Check if sops is installed."""
    try:
        subprocess.run(["sops", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def check_age_installed() -> bool:
    """Check if age is installed."""
    try:
        subprocess.run(["age", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def decrypt_secrets(secrets_file: Path = None) -> dict:
    """Decrypt secrets file and return as dict."""
    secrets_file = secrets_file or DEFAULT_SECRETS_FILE

    if not secrets_file.exists():
        raise SecretsNotFoundError(f"Secrets file not found: {secrets_file}")

    result = subprocess.run(
        ["sops", "-d", str(secrets_file)],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise SOPSError(f"Failed to decrypt: {result.stderr}")

    return yaml.safe_load(result.stdout) or {}


def list_keys(secrets_file: Path = None) -> list[str]:
    """List all secret keys (without values - safe for LLM)."""
    secrets = decrypt_secrets(secrets_file)
    return sorted(secrets.keys())


def get_secret(key: str, secrets_file: Path = None) -> str:
    """Get a secret value (UNSAFE for LLM - use peek instead)."""
    secrets = decrypt_secrets(secrets_file)

    if key not in secrets:
        raise KeyNotFoundError(f"Key not found: {key}")

    return str(secrets[key])


def peek_secret(key: str, peek_chars: int = 4, secrets_file: Path = None) -> str:
    """
    Get a masked preview of a secret (SAFE for LLM).

    Returns format like: "sk-12********cdef"
    """
    value = get_secret(key, secrets_file)
    return mask_value(value, peek_chars)


def set_secret(key: str, value: str, secrets_file: Path = None) -> None:
    """Set a secret value."""
    secrets_file = secrets_file or DEFAULT_SECRETS_FILE

    # Ensure parent directory exists
    secrets_file.parent.mkdir(parents=True, exist_ok=True)

    if secrets_file.exists():
        # Decrypt existing secrets
        secrets = decrypt_secrets(secrets_file)
    else:
        secrets = {}

    # Update the secret
    secrets[key] = value

    # Write to temp file and encrypt
    temp_file = secrets_file.with_suffix(".yaml.tmp")
    try:
        with open(temp_file, "w") as f:
            yaml.dump(secrets, f, default_flow_style=False)

        # Encrypt with sops
        result = subprocess.run(
            ["sops", "-e", "-i", str(temp_file)],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            raise SOPSError(f"Failed to encrypt: {result.stderr}")

        # Move to final location
        temp_file.rename(secrets_file)

    finally:
        # Clean up temp file if it still exists
        if temp_file.exists():
            temp_file.unlink()


def delete_secret(key: str, secrets_file: Path = None) -> None:
    """Delete a secret."""
    secrets_file = secrets_file or DEFAULT_SECRETS_FILE

    if not secrets_file.exists():
        raise SecretsNotFoundError(f"Secrets file not found: {secrets_file}")

    secrets = decrypt_secrets(secrets_file)

    if key not in secrets:
        raise KeyNotFoundError(f"Key not found: {key}")

    del secrets[key]

    # Write back
    temp_file = secrets_file.with_suffix(".yaml.tmp")
    try:
        with open(temp_file, "w") as f:
            yaml.dump(secrets, f, default_flow_style=False)

        result = subprocess.run(
            ["sops", "-e", "-i", str(temp_file)],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            raise SOPSError(f"Failed to encrypt: {result.stderr}")

        temp_file.rename(secrets_file)

    finally:
        if temp_file.exists():
            temp_file.unlink()


def init_secrets_file(secrets_file: Path = None, age_recipient: str = None) -> None:
    """Initialize a new secrets file."""
    secrets_file = secrets_file or DEFAULT_SECRETS_FILE

    if secrets_file.exists():
        raise SecretsError(f"Secrets file already exists: {secrets_file}")

    # Ensure directory exists
    secrets_file.parent.mkdir(parents=True, exist_ok=True)

    # Get age recipient from key file if not provided
    if not age_recipient:
        if AGE_KEY_FILE.exists():
            # Extract public key from private key file
            result = subprocess.run(
                ["age-keygen", "-y", str(AGE_KEY_FILE)],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                age_recipient = result.stdout.strip()

    if not age_recipient:
        raise SecretsError(
            "No age recipient found. Either:\n"
            "  1. Create age key: age-keygen -o ~/.config/sops/age/keys.txt\n"
            "  2. Or provide --age-recipient"
        )

    # Create initial secrets file
    initial_content = {"_example": "replace-me"}

    temp_file = secrets_file.with_suffix(".yaml.tmp")
    try:
        with open(temp_file, "w") as f:
            yaml.dump(initial_content, f, default_flow_style=False)

        # Create .sops.yaml config if it doesn't exist
        sops_config = secrets_file.parent / ".sops.yaml"
        if not sops_config.exists():
            with open(sops_config, "w") as f:
                f.write(f"creation_rules:\n  - age: {age_recipient}\n")

        # Encrypt
        result = subprocess.run(
            ["sops", "-e", "-i", str(temp_file)],
            capture_output=True,
            text=True,
            cwd=secrets_file.parent
        )

        if result.returncode != 0:
            raise SOPSError(f"Failed to encrypt: {result.stderr}")

        temp_file.rename(secrets_file)

    finally:
        if temp_file.exists():
            temp_file.unlink()
