#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.14"
# dependencies = [
#     "claude-agent-sdk>=0.1.0",
#     "click>=8.0.0",
#     "rich>=13.0.0",
#     "tomli>=2.0.0",
# ]
# ///
"""
lx - Linux command assistant (Claude-powered)

A small CLI that lets you ask a Linux-focused assistant for step-by-step guidance,
including example commands, explanations, best practices, and safety warnings.

This tool follows the repository's established uv-script + Click CLI pattern and
reuses shared utilities from `common_utils.py` (console formatting, config,
logging, Claude SDK wrapper, and consistent error handling).

Usage examples:

  # Ask a question (instruction must be quoted)
  ./lx.py ask "show disk usage"

  # With verbose logging
  ./lx.py -v ask "configure firewall to allow port 8080"

  # Enable Rich Markdown formatting
  ./lx.py --markdown ask "list all users on the system"

  # Run diagnostic checks
  ./lx.py doctor

Features:
  - Uses Claude Sonnet by default for faster responses (configurable)
  - Plain text output by default; use --markdown for Rich formatted output
  - Structured prompt limits Claude to 1-3 commands for clean extraction
  - Extracts bash/sh/shell fenced code blocks
  - Interactive command selection and execution
  - Destructive command detection for rm, dd, mkfs, chmod, systemctl operations

Configuration:
  - Model can be configured via ~/.config/aca/config.toml (default_model key)
    or ACA_DEFAULT_MODEL environment variable (defaults to "sonnet")

Requirements:
  - Claude Code CLI (https://claude.ai/download)
"""

import logging
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import click
import tomli
from rich.console import Console
from rich.markdown import Markdown

from common_utils import (
    ACAError,
    check_claude_cli,
    check_network_connectivity,
    generate_with_progress,
    get_config,
    get_console,
    print_error,
    setup_logging,
)

logger = logging.getLogger(__name__)


LINUX_ENGINEER_PROMPT = """You are a Linux engineer. Provide concise, practical answers.

RESPONSE FORMAT:
1. Show 1-3 commands maximum in separate code blocks with no explanations or comments inside code blocks. Show only the commands.
2. Show the commands in the order of their importance.

Example response format:
```bash
command-here
```

```bash
another-command
```
"""


def extract_commands(response: str) -> list[str]:
    """Extract executable commands from a Claude response.

    Extracts fenced code blocks with bash/sh/shell language identifiers.
    The prompt instructs Claude to use separate code blocks for each command,
    making extraction straightforward.

    Returns:
      A list of command strings, deduplicated.
    """
    commands: list[str] = []
    seen: set[str] = set()

    # Code blocks: ```bash ...```, ```sh ...```, ```shell ...```
    code_block_pattern = re.compile(
        r"```(?:bash|sh|shell)\r?\n(.*?)```",
        re.DOTALL | re.IGNORECASE,
    )
    for match in code_block_pattern.finditer(response):
        block = match.group(1).strip()
        if not block:
            continue
        # Remove prompt prefixes if present
        cleaned = re.sub(r"^\s*[$#]\s+", "", block, flags=re.MULTILINE).strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            commands.append(cleaned)

    return commands


def is_destructive_command(command: str) -> bool:
    """Best-effort detection of potentially destructive commands.

    Detection strategy:
      1. Pattern matching against known destructive command prefixes
      2. Context-sensitive analysis for commands like `rm` (checks for -rf flags, root paths)
      3. Flag-based detection (e.g., --no-preserve-root)

    Pattern categories:
      - Filesystem destructive: rm, dd, mkfs, fdisk, parted, shred, wipefs, truncate
      - Permissions/ownership: chmod, chown (can lock out access)
      - Process-killing: kill -9, pkill, killall
      - System control: systemctl stop/disable, reboot, shutdown, halt, poweroff, init 0/6

    Context-sensitive logic for `rm`:
      - Always flagged as potentially destructive
      - Extra scrutiny for recursive/force flags (-rf, --recursive, --force)
      - Critical warning for root paths (/, /*)
    """
    cmd = command.strip()
    if not cmd:
        return False

    lowered = cmd.lower()

    # High-risk patterns (broad signal).
    patterns: list[re.Pattern[str]] = [
        # Filesystem / disk destructive
        re.compile(r"(^|[;&|()]\s*)rm(\s|$)", re.IGNORECASE),
        re.compile(r"(^|[;&|()]\s*)dd(\s|$)", re.IGNORECASE),
        re.compile(r"(^|[;&|()]\s*)mkfs(\.|(\s|$))", re.IGNORECASE),
        re.compile(r"(^|[;&|()]\s*)(fdisk|parted)(\s|$)", re.IGNORECASE),
        re.compile(r"(^|[;&|()]\s*)(shred|wipefs)(\s|$)", re.IGNORECASE),
        re.compile(r"(^|[;&|()]\s*)(truncate)(\s|$)", re.IGNORECASE),
        # Windows-esque destructive (still worth flagging)
        re.compile(r"(^|[;&|()]\s*)(del|format)(\s|$)", re.IGNORECASE),
        # Permissions / ownership / service disruption
        re.compile(r"(^|[;&|()]\s*)chmod(\s|$)", re.IGNORECASE),
        re.compile(r"(^|[;&|()]\s*)chown(\s|$)", re.IGNORECASE),
        re.compile(r"(^|[;&|()]\s*)systemctl\s+(stop|disable)(\s|$)", re.IGNORECASE),
        # Process-killing / rebooting
        re.compile(r"(^|[;&|()]\s*)kill\s+-9(\s|$)", re.IGNORECASE),
        re.compile(r"(^|[;&|()]\s*)(pkill|killall)(\s|$)", re.IGNORECASE),
        re.compile(
            r"(^|[;&|()]\s*)(reboot|shutdown|halt|poweroff)(\s|$)",
            re.IGNORECASE,
        ),
        re.compile(r"(^|[;&|()]\s*)init\s+[06](\s|$)", re.IGNORECASE),
    ]

    if any(p.search(cmd) for p in patterns):
        # Context-sensitive downgrades / upgrades.
        # rm: prioritize strong signals like recursive/force and root paths.
        if re.search(r"(^|[;&|()]\s*)rm(\s|$)", cmd, re.IGNORECASE):
            rm_is_recursive = re.search(
                r"\s-(?:[^\n]*r[^\n]*f|[^\n]*f[^\n]*r)", lowered
            )
            rm_has_flags = re.search(
                r"\s--(recursive|force|no-preserve-root)\b", lowered
            )
            rm_targets_root = re.search(r"(\s|^)(/|/\*|/\s*$)", cmd)
            if rm_targets_root and (rm_is_recursive or rm_has_flags):
                return True
            # Still treat recursive/force as destructive even on non-root targets.
            if rm_is_recursive or rm_has_flags:
                return True
            # A plain "rm file" is potentially destructive but common; keep it flagged.
            return True

        # chmod 000 is a strong footgun.
        if re.search(r"(^|[;&|()]\s*)chmod\s+000\b", lowered):
            return True

        # systemctl stop/disable on critical targets can be disruptive; treat as destructive.
        return True

    # Additional strong signals even if the base command isn't in the list.
    if " --no-preserve-root" in lowered:
        return True

    return False


def execute_command(command: str, console: Console) -> tuple[bool, int]:
    """Execute a shell command and print stdout/stderr."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300,
            check=True,
        )
        if result.stdout:
            console.print(result.stdout.rstrip("\n"))
        return True, result.returncode
    except subprocess.TimeoutExpired:
        print_error(console, "Command timed out after 300 seconds")
        return False, 124
    except subprocess.CalledProcessError as e:
        if e.stdout:
            console.print(e.stdout.rstrip("\n"))
        if e.stderr:
            print_error(console, e.stderr.rstrip("\n"))
        else:
            print_error(console, f"Command failed with exit code {e.returncode}")
        return False, e.returncode
    except FileNotFoundError as e:
        print_error(console, f"Command execution failed: {e}")
        return False, 127


def confirm_destructive_command(command: str, console: Console) -> bool:
    """Confirm execution of a potentially destructive command."""
    console.print(
        "[yellow]Warning:[/yellow] This command may delete files, modify system configuration, or cause data loss."
    )
    if console.no_color:
        console.print(f"Command:\n{command}")
    else:
        console.print(Markdown(f"```bash\n{command}\n```"))
    answer = input(
        "Are you sure you want to execute this command? Type 'yes' to confirm: "
    )
    return answer == "yes"


def handle_commands_interactively(
    commands: list[str], console: Console, verbose: bool
) -> None:
    """Show extracted commands and let user select one to execute."""
    # Filter empty commands
    commands = [c.strip() for c in commands if c.strip()]

    if not commands:
        return

    try:
        # Show numbered list of commands
        for i, cmd in enumerate(commands, 1):
            console.print(f"{i}. {cmd}")

        # Prompt for selection
        selection = input("Which command to run? (number or Enter to skip): ").strip()
        if not selection:
            return

        try:
            idx = int(selection)
            if idx < 1 or idx > len(commands):
                print_error(console, f"Invalid selection. Enter 1-{len(commands)}")
                return
        except ValueError:
            print_error(console, "Invalid input. Enter a number.")
            return

        cmd = commands[idx - 1]
        if verbose:
            logger.debug(
                "User selected command %d: %s", idx, cmd[:50].replace("\n", " ")
            )

        # Check for destructive commands
        if is_destructive_command(cmd):
            if not confirm_destructive_command(cmd, console):
                console.print("Skipped.")
                return

        # Execute the command
        execute_command(cmd, console)

    except KeyboardInterrupt:
        console.print("\nCancelled.")


@click.group()
@click.option("--markdown", is_flag=True, help="Enable Rich Markdown formatting")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose/debug logging")
@click.pass_context
def cli(ctx: click.Context, markdown: bool, verbose: bool) -> None:
    """Linux command assistant (Claude-powered).

    Use 'lx ask "your question"' to ask a question.
    Use 'lx doctor' to run diagnostic checks.
    """
    ctx.ensure_object(dict)
    ctx.obj["markdown"] = markdown
    ctx.obj["verbose"] = verbose
    setup_logging(verbose)


@cli.command()
@click.argument("instruction", required=True)
@click.pass_context
def ask(ctx: click.Context, instruction: str) -> None:
    """Ask a Linux question. INSTRUCTION must be quoted.

    Example: lx ask "show disk usage"
    """
    markdown = ctx.obj.get("markdown", False)
    verbose = ctx.obj.get("verbose", False)
    config = get_config()

    console = get_console(plain_text=not markdown)
    if not check_claude_cli(console):
        sys.exit(1)

    full_prompt = f"{LINUX_ENGINEER_PROMPT}\n\nUser Request: {instruction}"

    try:
        response = generate_with_progress(
            console=console,
            prompt=full_prompt,
            cwd=str(Path.cwd()),
            message="Consulting Linux engineer...",
            model=config.default_model,
        )
    except ACAError as e:
        print_error(console, e.format_error())
        sys.exit(1)
    except Exception as e:
        print_error(console, f"Unexpected error: {e}")
        sys.exit(1)

    extracted = extract_commands(response)
    if verbose:
        logger.debug("Extracted %d command block(s) from response", len(extracted))

    handle_commands_interactively(extracted, console, verbose)


@cli.command()
@click.pass_context
def doctor(ctx: click.Context) -> None:
    """Run diagnostic checks for lx dependencies.

    Checks:
    - Claude Code CLI installation and version
    - Claude Code CLI authentication
    - claude-agent-sdk version
    - Network connectivity to Anthropic API
    - Configuration file validity
    """
    markdown = ctx.obj.get("markdown", False)
    console = get_console(plain_text=not markdown)

    console.print("[bold]lx Diagnostic Report[/bold]\n")

    all_passed = True

    # Check Claude Code CLI
    console.print("Checking Claude Code CLI... ", end="")
    if shutil.which("claude"):
        try:
            result = subprocess.run(
                ["claude", "--version"], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                cli_version = result.stdout.strip()
                console.print(f"[green]✓[/green] {cli_version}")
            else:
                console.print("[red]✗ Failed to get version[/red]")
                console.print(
                    "  [yellow]Install from https://claude.ai/download[/yellow]"
                )
                all_passed = False
        except subprocess.TimeoutExpired:
            console.print("[red]✗ Timed out[/red]")
            all_passed = False
        except Exception as e:
            console.print(f"[red]✗ Error: {e}[/red]")
            all_passed = False
    else:
        console.print("[red]✗ Not found[/red]")
        console.print("  [yellow]Install from https://claude.ai/download[/yellow]")
        all_passed = False

    # Check Claude Code CLI authentication
    console.print("Checking Claude Code CLI auth... ", end="")
    has_api_key = os.environ.get("ANTHROPIC_API_KEY") is not None
    credentials_file = Path.home() / ".claude" / ".credentials.json"
    has_credentials_file = credentials_file.exists()

    if has_api_key:
        console.print("[green]✓[/green] Authenticated (via API key)")
    elif has_credentials_file:
        try:
            import json

            with open(credentials_file, "r") as f:
                creds = json.load(f)
            if creds:
                console.print("[green]✓[/green] Authenticated (via credentials file)")
            else:
                console.print(
                    "[yellow]⚠[/yellow] Credentials file exists but appears empty"
                )
                all_passed = False
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] Could not validate credentials: {e}")
            all_passed = False
    else:
        console.print("[red]✗ Not authenticated[/red]")
        console.print(
            "  [yellow]Run 'claude' and sign in, or set ANTHROPIC_API_KEY[/yellow]"
        )
        all_passed = False

    # Check claude-agent-sdk
    console.print("Checking claude-agent-sdk... ", end="")
    try:
        from importlib.metadata import version

        sdk_version = version("claude-agent-sdk")
        console.print(f"[green]✓[/green] {sdk_version}")
    except Exception:
        console.print("[red]✗ Not found[/red]")
        console.print("  [yellow]Install with: pip install claude-agent-sdk[/yellow]")
        all_passed = False

    # Check network connectivity
    console.print("Checking network connectivity... ", end="")
    connected, network_error = check_network_connectivity()
    if connected:
        console.print("[green]✓[/green] api.anthropic.com reachable")
    else:
        console.print(f"[red]✗ {network_error}[/red]")
        console.print(
            "  [yellow]Check your internet connection and firewall settings[/yellow]"
        )
        all_passed = False

    # Check configuration
    console.print("Checking configuration... ", end="")
    config_path = Path.home() / ".config" / "aca" / "config.toml"
    if config_path.exists():
        try:
            with open(config_path, "rb") as f:
                tomli.load(f)
            console.print(f"[green]✓[/green] Config file found ({config_path})")
            config = get_config()
            console.print(f"    Default model: {config.default_model}")
            console.print(f"    Timeout: {config.timeout}s")
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] Config file has errors: {e}")
    else:
        console.print("[blue]ℹ[/blue] No config file (using defaults)")
        config = get_config()
        console.print(f"    Default model: {config.default_model} (default)")
        console.print(f"    Timeout: {config.timeout}s (default)")

    # Summary
    console.print()
    if all_passed:
        console.print("[green]All checks passed![/green]")
    else:
        console.print("[yellow]Some checks failed. Review the output above.[/yellow]")
        sys.exit(1)


if __name__ == "__main__":
    cli()  # pylint: disable=no-value-for-parameter
