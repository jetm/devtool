#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.14"
# dependencies = [
#     "claude-agent-sdk>=0.1.0",
#     "click>=8.0.0",
#     "rich>=13.0.0",
#     "pyperclip>=1.8.0",
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

  # Basic usage
  ./lx.py "show disk usage"

  # Multi-word instruction
  ./lx.py show me all running processes sorted by memory usage

  # With verbose logging
  ./lx.py -v "configure firewall to allow port 8080"

  # Plain text output (no colors/formatting)
  ./lx.py --plain-text "list all users on the system"

Features:
  - Claude response rendered with Rich Markdown output (unless --plain-text)
  - Extracts bash/sh/shell fenced code blocks and inline prompt-style commands
    for later interactive handling (next phase)
  - Shares configuration via ~/.config/aca/config.toml through common utilities
"""

import logging
import re
import subprocess
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.markdown import Markdown

from common_utils import (
    ACAError,
    check_claude_cli,
    generate_with_progress,
    get_config,
    get_console,
    print_error,
    print_output,
    setup_logging,
)

logger = logging.getLogger(__name__)


LINUX_ENGINEER_PROMPT = """I want you to act as a **Linux engineer with deep expertise in command-line operations, system administration, and troubleshooting**. You should be capable of providing detailed explanations and step-by-step guidance for any Linux-related tasks, including shell scripting, process management, networking, package management, permissions, backup, and security configurations. When I ask a question or describe a task, you will respond with **clear examples of commands**, describe what each command does, and include **best practices** and possible pitfalls to avoid. If there are multiple methods, explain their differences and when to use each.

Your tone should be professional, precise, and educational—imagine you are mentoring a junior system administrator. Always confirm important commands that could modify the system and explain any potential risks before execution.
"""


def extract_commands(response: str) -> list[str]:
    """Extract executable commands from a Claude response.

    Extracts:
      - Fenced code blocks with bash/sh/shell language identifiers.
      - Inline prompt-style commands (lines beginning with `$ ` or `# `).

    Returns:
      A list of command strings (may contain multi-line commands and chains).
    """
    commands: list[str] = []

    # Code blocks: ```bash ...```, ```sh ...```, ```shell ...```
    code_block_pattern = re.compile(
        r"```(?:bash|sh|shell)\r?\n(.*?)```",
        re.DOTALL | re.IGNORECASE,
    )
    for match in code_block_pattern.finditer(response):
        block = match.group(1).strip("\n")
        if not block.strip():
            continue

        # Remove prompt prefixes inside code blocks while preserving structure.
        cleaned_lines: list[str] = []
        for line in block.splitlines():
            cleaned_lines.append(re.sub(r"^\s*[$#]\s+", "", line))
        cleaned = "\n".join(cleaned_lines).strip()
        if cleaned:
            commands.append(cleaned)

    # Inline commands: lines beginning with "$ " or "# "
    lines = response.splitlines()
    inline_pattern = re.compile(r"^\s*[$#]\s+(.+)$")
    i = 0
    while i < len(lines):
        line = lines[i]
        m = inline_pattern.match(line)
        if not m:
            i += 1
            continue

        cmd_lines: list[str] = [m.group(1).rstrip()]
        while i + 1 < len(lines):
            cur = cmd_lines[-1].rstrip()
            if not cur:
                break
            if not (
                cur.endswith("\\")
                or cur.endswith("&&")
                or cur.endswith("|")
                or cur.endswith("(")
            ):
                break

            next_line = lines[i + 1]
            if not next_line.strip():
                break
            if next_line.lstrip().startswith("```"):
                break

            # Allow either continued indentation, or another prompt-prefixed line.
            next_match = inline_pattern.match(next_line)
            if next_match:
                cmd_lines.append(next_match.group(1).rstrip())
                i += 1
                continue

            cmd_lines.append(next_line.strip("\n").lstrip())
            i += 1

        cmd = "\n".join(cmd_lines).strip()
        if cmd:
            commands.append(cmd)

        i += 1

    return commands


def is_destructive_command(command: str) -> bool:
    """Best-effort detection of potentially destructive commands."""
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


def copy_to_clipboard(console: Console, text: str) -> bool:
    """Copy text to clipboard with helpful error messages."""
    try:
        import pyperclip  # pylint: disable=import-error
    except Exception as e:
        print_error(console, f"Clipboard unavailable (pyperclip import failed): {e}")
        console.print(
            "Please copy manually or install xclip/xsel (Linux) or pbcopy (macOS)."
        )
        return False

    try:
        pyperclip.copy(text)
        return True
    except (
        getattr(pyperclip, "PyperclipException", Exception),
        getattr(pyperclip, "PyperclipWindowsException", Exception),
        getattr(pyperclip, "PyperclipTimeoutException", Exception),
    ) as e:
        print_error(console, f"Clipboard unavailable: {e}")
        console.print(
            "Please copy manually or install xclip/xsel (Linux) or pbcopy (macOS)."
        )
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
        "[yellow]Warning:[/yellow] This command may delete files, modify system "
        "configuration, or cause data loss."
    )
    if console.no_color:
        console.print(f"Command:\n{command}")
    else:
        console.print(Markdown(f"```bash\n{command}\n```"))
    answer = input(
        "Are you sure you want to execute this command? Type 'yes' to confirm: "
    )
    return answer == "yes"


def _print_command_block(command: str, console: Console) -> None:
    if console.no_color:
        console.print(f"```\n{command}\n```")
    else:
        console.print(Markdown(f"```bash\n{command}\n```"))


def _prompt_action() -> str:
    return (
        input("What would you like to do? [C]opy / [E]xecute / [S]kip: ")
        .strip()
        .lower()
    )


def _normalize_commands(commands: list[str]) -> list[str]:
    cleaned: list[str] = []
    for c in commands:
        c2 = c.strip()
        if c2:
            cleaned.append(c2)
    return cleaned


def _parse_selection(selection: str, max_index: int) -> list[int] | None:
    s = selection.strip().lower()
    if s == "s":
        return []
    if s == "a":
        return list(range(1, max_index + 1))

    indices: set[int] = set()
    parts = [p.strip() for p in s.split(",") if p.strip()]
    if not parts:
        return None

    for part in parts:
        if "-" in part:
            lo_s, hi_s = (x.strip() for x in part.split("-", 1))
            if not lo_s.isdigit() or not hi_s.isdigit():
                return None
            lo = int(lo_s)
            hi = int(hi_s)
            if lo < 1 or hi < 1 or lo > max_index or hi > max_index or lo > hi:
                return None
            for i in range(lo, hi + 1):
                indices.add(i)
            continue
        if not part.isdigit():
            return None
        idx = int(part)
        if idx < 1 or idx > max_index:
            return None
        indices.add(idx)

    return sorted(indices)


def handle_commands_interactively(
    commands: list[str],
    console: Console,
    auto_copy: bool,
    verbose: bool,
) -> None:
    commands = _normalize_commands(commands)

    try:
        if auto_copy and commands:
            if verbose:
                logger.debug("Auto-copy enabled; copying first extracted command")
            success = copy_to_clipboard(console, commands[0])
            if verbose:
                logger.debug("Clipboard copy %s", "succeeded" if success else "failed")
            if success:
                console.print("Copied first command to clipboard.")
                return

        if not commands:
            console.print("No executable commands found in response")
            return

        def handle_one(cmd: str, idx: int | None = None) -> None:
            if idx is not None and verbose:
                logger.debug(
                    "User selected command %d: %s", idx, cmd[:50].replace("\n", " ")
                )

            _print_command_block(cmd, console)

            while True:
                choice = _prompt_action()
                if choice == "c":
                    success = copy_to_clipboard(console, cmd)
                    if verbose:
                        logger.debug(
                            "Clipboard copy %s", "succeeded" if success else "failed"
                        )
                    if success:
                        console.print("Copied to clipboard.")
                    return
                if choice == "e":
                    destructive = is_destructive_command(cmd)
                    if verbose:
                        logger.debug(
                            "Executing command with destructive check: %s",
                            destructive,
                        )
                    if destructive and not confirm_destructive_command(cmd, console):
                        console.print("Skipped.")
                        return
                    ok, exit_code = execute_command(cmd, console)
                    if verbose:
                        logger.debug(
                            "Command execution %s (exit_code=%d)",
                            "succeeded" if ok else "failed",
                            exit_code,
                        )
                    return
                if choice == "s":
                    return
                print_error(console, "Invalid choice. Please enter c, e, or s.")

        if len(commands) == 1:
            handle_one(commands[0], 1)
            return

        # Multiple commands
        console.print("Commands found:")
        for i, cmd in enumerate(commands, 1):
            preview = cmd.strip().splitlines()[0].strip()
            if len(preview) > 100:
                preview = preview[:97] + "..."
            suffix = " (multi-line)" if "\n" in cmd else ""
            console.print(f"[bold]{i}[/bold]. {preview}{suffix}")

        while True:
            sel = input("Select command number (or 'a' for all, 's' to skip): ").strip()
            parsed = _parse_selection(sel, len(commands))
            if parsed is None:
                print_error(
                    console,
                    "Invalid selection. Use a number, 'a', 's', or comma/range like 1,3 or 2-4.",
                )
                continue
            if parsed == []:
                return
            for idx in parsed:
                handle_one(commands[idx - 1], idx)
            return

    except KeyboardInterrupt:
        console.print("\nCancelled.")
        return


@click.command()
@click.argument("instruction", required=True, nargs=-1)
@click.option("--plain-text", is_flag=True, help="Output plain text without formatting")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose/debug logging")
@click.option(
    "--auto-copy",
    is_flag=True,
    help="Automatically copy first command to clipboard",
)
def main(
    instruction: tuple[str, ...],
    plain_text: bool,
    verbose: bool,
    auto_copy: bool,
) -> None:
    setup_logging(verbose)
    _ = get_config()  # Ensure shared config is loaded (and keeps import used).

    instruction_text = " ".join(instruction)
    if not instruction_text.strip():
        console = get_console(plain_text)
        print_error(console, "Instruction is required")
        sys.exit(1)

    console = get_console(plain_text)
    if not check_claude_cli(console):
        sys.exit(1)

    full_prompt = f"{LINUX_ENGINEER_PROMPT}\n\nUser Request: {instruction_text}"

    try:
        response = generate_with_progress(
            console=console,
            prompt=full_prompt,
            cwd=str(Path.cwd()),
            message="Consulting Linux engineer...",
        )
    except ACAError as e:
        print_error(console, e.format_error())
        sys.exit(1)
    except Exception as e:
        print_error(console, f"Unexpected error: {e}")
        sys.exit(1)

    print_output(console, response, markdown=True)
    extracted = extract_commands(response)
    if verbose:
        logger.debug("Extracted %d command block(s) from response", len(extracted))
    if extracted:
        console.print("\n" + ("-" * 80) + "\n")

    handle_commands_interactively(extracted, console, auto_copy, verbose)


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
