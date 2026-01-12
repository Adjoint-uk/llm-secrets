"""
llm-secrets - SOPS wrapper for the AI agent era.

Manage encrypted secrets without leaking them to LLM context.

Features:
- peek: View masked secrets (safe for LLM context)
- set: Add secrets via hidden input (not in shell history)
- exec: Run commands with secrets injected (never visible to LLM)
- list: Show available keys (no values)

Requires: sops, age (for encryption)
"""

__version__ = "0.1.0"
