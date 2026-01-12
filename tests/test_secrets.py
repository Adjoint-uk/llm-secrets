"""Tests for llm-secrets."""

import pytest
from llm_secrets.secrets import mask_value


class TestMaskValue:
    """Tests for the mask_value function - the core LLM safety feature."""

    def test_mask_normal_value(self):
        """Normal values show first/last N chars."""
        result = mask_value("sk-1234567890abcdef", peek_chars=4)
        assert result == "sk-1********cdef"
        assert "1234567890ab" not in result  # Middle hidden

    def test_mask_short_value(self):
        """Short values are fully masked."""
        result = mask_value("secret", peek_chars=4)
        assert result == "******"
        assert "secret" not in result

    def test_mask_empty_value(self):
        """Empty values return indicator."""
        result = mask_value("")
        assert result == "(empty)"

    def test_mask_exact_boundary(self):
        """Values exactly 2*peek_chars are fully masked."""
        result = mask_value("12345678", peek_chars=4)
        assert result == "********"

    def test_mask_custom_peek_chars(self):
        """Custom peek_chars works."""
        result = mask_value("abcdefghijklmnop", peek_chars=2)
        assert result.startswith("ab")
        assert result.endswith("op")

    def test_mask_long_middle(self):
        """Long middles are capped at 8 asterisks."""
        result = mask_value("a" * 100, peek_chars=4)
        # Should be: aaaa********aaaa (8 asterisks max in middle)
        assert result == "aaaa********aaaa"


class TestConfig:
    """Tests for configuration."""

    def test_xdg_config_respected(self, monkeypatch, tmp_path):
        """XDG_CONFIG_HOME is respected."""
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

        # Re-import to pick up new env
        from llm_secrets import config
        result = config.get_config_dir()

        assert str(tmp_path) in str(result)

    def test_env_override_secrets_file(self, monkeypatch, tmp_path):
        """LLM_SECRETS_FILE env var overrides default."""
        custom_path = tmp_path / "custom.yaml"
        monkeypatch.setenv("LLM_SECRETS_FILE", str(custom_path))

        from llm_secrets import config
        # Need to call function directly, not use cached constant
        result = config.get_default_secrets_file()

        assert result == custom_path


class TestCLI:
    """Tests for CLI argument parsing."""

    def test_help_exits_zero(self):
        """--help exits with code 0."""
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, "-m", "llm_secrets.cli", "--help"],
            capture_output=True
        )
        assert result.returncode == 0
        assert b"llm-secrets" in result.stdout

    def test_version_shows_version(self):
        """--version shows version."""
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, "-m", "llm_secrets.cli", "--version"],
            capture_output=True
        )
        assert result.returncode == 0
        assert b"0.1.0" in result.stdout
