"""Shared git utilities — editor, text processing, error recovery."""

from __future__ import annotations

import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rich.console import Console

logger = logging.getLogger(__name__)

# Patterns matching common LLM preamble lines that should be skipped during title parsing
PREAMBLE_PATTERNS = re.compile(
    r"^(here'?s|here is|below is|the following|sure|okay|i'?ve|let me)",
    re.IGNORECASE,
)


def edit_in_editor(content: str, console: Console, file_suffix: str = ".txt") -> str:
    """Open content in user's editor for editing.

    Uses editor from config.toml first, then environment variables in order:
    $EDITOR, $VISUAL, then falls back to nano, then vi.
    """
    from devtool.common.config import get_config
    from devtool.common.console import print_error

    def try_find_editor(editor_cmd: str | None) -> tuple[list[str], str | None] | None:
        if not editor_cmd:
            return None
        try:
            parts = shlex.split(editor_cmd)
        except ValueError:
            return None
        if not parts:
            return None
        resolved = shutil.which(parts[0])
        if resolved:
            return (parts, resolved)
        return None

    config_editor = get_config().editor
    editor_sources = [
        ("config.toml", config_editor),
        ("$EDITOR", os.environ.get("EDITOR")),
        ("$VISUAL", os.environ.get("VISUAL")),
        ("fallback", "nano"),
        ("fallback", "vi"),
    ]

    editor_parts: list[str] | None = None
    for source_name, editor_cmd in editor_sources:
        result = try_find_editor(editor_cmd)
        if result:
            editor_parts, resolved_path = result
            break
        elif editor_cmd and source_name in ("config.toml", "$EDITOR", "$VISUAL"):
            console.print(
                f"[yellow]Warning:[/yellow] {source_name}={editor_cmd!r} not found or invalid, trying next option..."
            )

    if not editor_parts:
        print_error(
            console,
            "No editor found. Please set $EDITOR environment variable.",
        )
        return content

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=file_suffix,
            delete=False,
            encoding="utf-8",
        ) as tmp_file:
            tmp_file.write(content)
            tmp_path = tmp_file.name
    except OSError as e:
        print_error(console, f"Failed to create temporary file: {e}")
        return content

    try:
        cmd = editor_parts + [tmp_path]
        try:
            proc_result = subprocess.run(cmd, check=False)
        except FileNotFoundError:
            print_error(console, f"Editor executable not found: {editor_parts[0]!r}")
            console.print("Using original content.")
            return content

        if proc_result.returncode != 0:
            print_error(console, f"Editor exited with code {proc_result.returncode}")
            console.print("Using original content.")
            return content

        try:
            with open(tmp_path, encoding="utf-8") as f:
                edited_content = f.read()
            return edited_content
        except OSError as e:
            print_error(console, f"Failed to read edited file: {e}")
            return content
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def extract_ticket_number(branch_name: str) -> str | None:
    """Extract IOTIL ticket number from branch name."""
    match = re.match(r"^[Ii][Oo][Tt][Ii][Ll]-(\d+)", branch_name)
    if match:
        return match.group(1)
    return None


def strip_markdown_code_blocks(text: str) -> str:
    """Remove markdown code block wrappers from text."""
    KNOWN_LANG_IDENTIFIERS = {"markdown", "commit", "text", "txt"}

    lines = text.strip().split("\n")
    if len(lines) >= 2 and lines[0].startswith("```") and lines[-1] == "```":
        opening_fence = lines[0].strip()
        content_lines = lines[1:-1]

        if opening_fence == "```" and content_lines and content_lines[0].strip().lower() in KNOWN_LANG_IDENTIFIERS:
            content_lines = content_lines[1:]

        while content_lines and content_lines[0].strip() in ("...", ""):
            content_lines = content_lines[1:]

        while content_lines and content_lines[-1].strip() in ("...", ""):
            content_lines = content_lines[:-1]

        return "\n".join(content_lines).strip()
    return text


def get_target_branch_from_config(repo: object) -> str | None:
    """Get the target branch for MR from git config.

    Reads the branch-switch.name config value, which is set by devtool switch-main
    when detecting/caching the main branch.
    """
    try:
        main_branch = repo.config_reader().get_value("branch-switch", "name")
        if main_branch:
            return str(main_branch)
    except Exception:
        pass
    return None


def handle_generation_error(
    console: Console,
    error: Exception,
    fallback_content: str | None = None,
    operation: str = "generation",
) -> str | None:
    """Handle generation errors with appropriate messages and fallback.

    Returns fallback content if user chooses to use it, None to signal retry.
    Raises SystemExit if user aborts.
    """
    from devtool.common.console import print_error
    from devtool.common.errors import RETRYABLE_EXCEPTIONS, ACAError

    logger.debug(f"Full error details for {operation}:", exc_info=True)

    if isinstance(error, ACAError):
        if console.no_color:
            console.print(error.format_error())
        else:
            console.print(f"[red]{error.format_error()}[/red]")
    else:
        print_error(console, f"Failed during {operation}: {error}")

    if fallback_content:
        console.print()
        if isinstance(error, RETRYABLE_EXCEPTIONS):
            console.print("[yellow]This appears to be a transient error. You can retry or use a template.[/yellow]")

        try:
            choice = input("Would you like to (r)etry, use (t)emplate, or (a)bort? [r/t/a]: ").strip().lower()
        except EOFError, KeyboardInterrupt:
            console.print("\nAborted.")
            sys.exit(0)

        if choice in ("r", "retry"):
            return None
        elif choice in ("t", "template"):
            console.print("\n[yellow]Opening editor with template...[/yellow]")
            return fallback_content
        elif choice in ("a", "abort"):
            console.print("Operation cancelled.")
            sys.exit(0)
        else:
            console.print("Invalid choice. Aborting.")
            sys.exit(1)
    else:
        sys.exit(1)

    return None
