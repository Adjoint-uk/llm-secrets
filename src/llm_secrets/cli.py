"""CLI for llm-secrets - SOPS wrapper for the AI agent era."""

import argparse
import getpass
import os
import subprocess
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from . import __version__
from .config import DEFAULT_SECRETS_FILE, AGE_KEY_FILE
from . import secrets

console = Console()
err_console = Console(stderr=True)


def cmd_list(args):
    """List all secret keys (values never shown - safe for LLM)."""
    try:
        keys = secrets.list_keys(args.file)

        if not keys:
            console.print("[dim]No secrets found.[/dim]")
            return 0

        table = Table(title="Available Secrets", show_header=True)
        table.add_column("Key", style="cyan")
        table.add_column("Status", style="green")

        for key in keys:
            if key.startswith("_"):
                table.add_row(key, "[dim]internal[/dim]")
            else:
                table.add_row(key, "available")

        console.print(table)
        console.print(f"\n[dim]Total: {len(keys)} secrets[/dim]")
        console.print("[dim]Use 'llm-secrets peek <key>' to view masked value[/dim]")
        return 0

    except secrets.SecretsNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        console.print("[dim]Initialize with: llm-secrets init[/dim]")
        return 1
    except secrets.SOPSError as e:
        console.print(f"[red]SOPS Error:[/red] {e}")
        return 1


def cmd_peek(args):
    """
    View a masked secret (SAFE for LLM context).

    Shows format like: sk-12********cdef
    The full secret is never exposed to the LLM.
    """
    try:
        masked = secrets.peek_secret(args.key, args.chars, args.file)
        console.print(f"[cyan]{args.key}:[/cyan] {masked}")

        # Show metadata
        full_value = secrets.get_secret(args.key, args.file)
        console.print(f"[dim]Length: {len(full_value)} chars[/dim]")

        return 0

    except secrets.KeyNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        console.print("[dim]Use 'llm-secrets list' to see available keys[/dim]")
        return 1
    except secrets.SecretsError as e:
        console.print(f"[red]Error:[/red] {e}")
        return 1


def cmd_get(args):
    """
    Get full secret value (UNSAFE for LLM - use in scripts only).

    WARNING: This outputs the full secret. Only use in:
    - Shell scripts that pipe the output
    - Automation that needs the actual value
    - Never in interactive LLM sessions
    """
    try:
        value = secrets.get_secret(args.key, args.file)
        # Output raw value (no newline for piping)
        print(value, end="")
        return 0

    except secrets.SecretsError as e:
        console.print(f"[red]Error:[/red] {e}", file=sys.stderr)
        return 1


def cmd_set(args):
    """
    Set a secret value via hidden input (safe - not in shell history).

    The value is read from:
    1. --value flag (NOT recommended - visible in shell history)
    2. --from-file (reads from file, then deletes file)
    3. Interactive hidden prompt (recommended)
    """
    try:
        if args.value:
            # Direct value (not recommended but useful for scripts)
            value = args.value
            console.print("[yellow]Warning:[/yellow] Value visible in shell history")

        elif args.from_file:
            # Read from file
            file_path = Path(args.from_file).expanduser()
            if not file_path.exists():
                console.print(f"[red]Error:[/red] File not found: {file_path}")
                return 1

            value = file_path.read_text().strip()

            # Delete the file after reading (security)
            if args.delete_file:
                file_path.unlink()
                console.print(f"[dim]Deleted source file: {file_path}[/dim]")

        else:
            # Interactive hidden input (recommended)
            console.print(f"[cyan]Setting secret:[/cyan] {args.key}")
            value = getpass.getpass("Enter value (hidden): ")

            if not value:
                console.print("[red]Error:[/red] Empty value not allowed")
                return 1

            # Confirm
            confirm = getpass.getpass("Confirm value (hidden): ")
            if value != confirm:
                console.print("[red]Error:[/red] Values don't match")
                return 1

        # Set the secret
        secrets.set_secret(args.key, value, args.file)

        # Show masked preview
        masked = secrets.mask_value(value)
        console.print(f"[green]Set:[/green] {args.key} = {masked}")
        return 0

    except secrets.SecretsError as e:
        console.print(f"[red]Error:[/red] {e}")
        return 1


def cmd_delete(args):
    """Delete a secret."""
    try:
        if not args.force:
            # Show what we're deleting
            masked = secrets.peek_secret(args.key, secrets_file=args.file)
            console.print(f"[yellow]Delete:[/yellow] {args.key} = {masked}")
            confirm = input("Type 'yes' to confirm: ")
            if confirm.lower() != "yes":
                console.print("[dim]Cancelled[/dim]")
                return 0

        secrets.delete_secret(args.key, args.file)
        console.print(f"[green]Deleted:[/green] {args.key}")
        return 0

    except secrets.SecretsError as e:
        console.print(f"[red]Error:[/red] {e}")
        return 1


def cmd_exec(args):
    """
    Execute a command with secrets injected as environment variables.

    The secrets are injected into the subprocess environment and never
    appear in the LLM context or shell history.

    Example:
        llm-secrets exec --inject API_KEY=my_api_key -- curl -H "Authorization: $API_KEY" https://api.example.com
    """
    try:
        # Strip leading '--' separator if present (argparse.REMAINDER includes it)
        command = args.exec_command
        if command and command[0] == "--":
            command = command[1:]

        if not command:
            err_console.print("[red]Error:[/red] No command specified")
            return 1

        # Build environment with injected secrets
        env = os.environ.copy()

        for inject in args.inject:
            if "=" not in inject:
                console.print(f"[red]Error:[/red] Invalid inject format: {inject}")
                console.print("[dim]Use: ENV_VAR=secret_key[/dim]")
                return 1

            env_var, secret_key = inject.split("=", 1)
            value = secrets.get_secret(secret_key, args.file)
            env[env_var] = value
            err_console.print(f"[dim]Injected: {env_var} (from {secret_key})[/dim]")

        # Run the command
        result = subprocess.run(command, env=env, shell=False)
        return result.returncode

    except secrets.SecretsError as e:
        err_console.print(f"[red]Error:[/red] {e}")
        return 1


def cmd_init(args):
    """Initialize a new secrets file."""
    try:
        secrets_file = args.file or DEFAULT_SECRETS_FILE

        if secrets_file.exists() and not args.force:
            console.print(f"[yellow]Warning:[/yellow] File already exists: {secrets_file}")
            console.print("[dim]Use --force to reinitialize[/dim]")
            return 1

        if args.force and secrets_file.exists():
            secrets_file.unlink()

        secrets.init_secrets_file(secrets_file, args.age_recipient)
        console.print(f"[green]Initialized:[/green] {secrets_file}")
        console.print("[dim]Add secrets with: llm-secrets set <key>[/dim]")
        return 0

    except secrets.SecretsError as e:
        console.print(f"[red]Error:[/red] {e}")
        return 1


def cmd_status(args):
    """Show status and configuration."""
    console.print("[bold]llm-secrets status[/bold]\n")

    # Check dependencies
    sops_ok = secrets.check_sops_installed()
    age_ok = secrets.check_age_installed()

    table = Table(show_header=True)
    table.add_column("Component", style="cyan")
    table.add_column("Status")
    table.add_column("Path/Info", style="dim")

    table.add_row(
        "sops",
        "[green]installed[/green]" if sops_ok else "[red]not found[/red]",
        "brew install sops" if not sops_ok else ""
    )

    table.add_row(
        "age",
        "[green]installed[/green]" if age_ok else "[red]not found[/red]",
        "brew install age" if not age_ok else ""
    )

    secrets_file = args.file or DEFAULT_SECRETS_FILE
    table.add_row(
        "secrets file",
        "[green]exists[/green]" if secrets_file.exists() else "[yellow]not found[/yellow]",
        str(secrets_file)
    )

    table.add_row(
        "age key",
        "[green]exists[/green]" if AGE_KEY_FILE.exists() else "[yellow]not found[/yellow]",
        str(AGE_KEY_FILE)
    )

    console.print(table)

    if secrets_file.exists():
        try:
            keys = secrets.list_keys(secrets_file)
            console.print(f"\n[dim]Secrets: {len(keys)} keys[/dim]")
        except Exception as e:
            console.print(f"\n[red]Cannot read secrets:[/red] {e}")

    return 0


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="llm-secrets",
        description="SOPS wrapper for the AI agent era - manage secrets without leaking them to LLM context",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  llm-secrets status                    # Check setup
  llm-secrets init                      # Initialize secrets file
  llm-secrets list                      # List keys (safe for LLM)
  llm-secrets peek api_key              # View masked secret (safe)
  llm-secrets set api_key               # Set via hidden input
  llm-secrets exec --inject API_KEY=api_key -- ./script.sh

LLM Safety:
  - 'list' and 'peek' are safe to use with LLMs
  - 'get' outputs full secret - use only in scripts
  - 'set' uses hidden input - never in shell history
  - 'exec' injects secrets without exposing them

Environment:
  LLM_SECRETS_FILE    Override default secrets file
  SOPS_AGE_KEY_FILE   Override age key location
        """
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-f", "--file", type=Path, help="Secrets file (default: ~/.config/llm-secrets/secrets.yaml)")

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # status
    subparsers.add_parser("status", help="Show status and configuration")

    # init
    init_parser = subparsers.add_parser("init", help="Initialize secrets file")
    init_parser.add_argument("--age-recipient", help="Age public key for encryption")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing file")

    # list
    subparsers.add_parser("list", help="List secret keys (safe for LLM)")

    # peek
    peek_parser = subparsers.add_parser("peek", help="View masked secret (safe for LLM)")
    peek_parser.add_argument("key", help="Secret key")
    peek_parser.add_argument("-c", "--chars", type=int, default=4, help="Chars to show (default: 4)")

    # get
    get_parser = subparsers.add_parser("get", help="Get full secret (UNSAFE - scripts only)")
    get_parser.add_argument("key", help="Secret key")

    # set
    set_parser = subparsers.add_parser("set", help="Set a secret (hidden input)")
    set_parser.add_argument("key", help="Secret key")
    set_parser.add_argument("--value", help="Value (NOT recommended - visible in history)")
    set_parser.add_argument("--from-file", help="Read value from file")
    set_parser.add_argument("--delete-file", action="store_true", help="Delete source file after reading")

    # delete
    delete_parser = subparsers.add_parser("delete", help="Delete a secret")
    delete_parser.add_argument("key", help="Secret key")
    delete_parser.add_argument("--force", action="store_true", help="Skip confirmation")

    # exec
    exec_parser = subparsers.add_parser("exec", help="Run command with secrets injected")
    exec_parser.add_argument("--inject", action="append", default=[], metavar="ENV=KEY",
                             help="Inject secret as env var (can repeat)")
    exec_parser.add_argument("exec_command", nargs=argparse.REMAINDER, help="Command to run")

    args = parser.parse_args()

    # Handle file path
    if args.file:
        args.file = Path(args.file).expanduser()

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "status":
        return cmd_status(args)
    elif args.command == "init":
        return cmd_init(args)
    elif args.command == "list":
        return cmd_list(args)
    elif args.command == "peek":
        return cmd_peek(args)
    elif args.command == "get":
        return cmd_get(args)
    elif args.command == "set":
        return cmd_set(args)
    elif args.command == "delete":
        return cmd_delete(args)
    elif args.command == "exec":
        return cmd_exec(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
