"""Rich console helpers, logging setup, and dependency checks."""

import logging
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from rich.console import Console
from rich.markdown import Markdown

logger = logging.getLogger(__name__)


def setup_logging(verbose: bool = False) -> None:
    """Configure logging based on verbosity and config."""
    from devtool.common.config import get_config

    config = get_config()
    level = logging.DEBUG if verbose else getattr(logging, config.log_level, logging.WARNING)

    root_logger = logging.getLogger()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter("[%(asctime)s] %(levelname)s [%(name)s:%(funcName)s:%(lineno)d] %(message)s")
    )
    root_logger.setLevel(level)
    root_logger.addHandler(handler)


def get_console(plain_text: bool) -> Console:
    """Get a Console instance configured for plain or rich output."""
    if plain_text:
        return Console(force_terminal=False, no_color=True, highlight=False)
    return Console()


def print_output(console: Console, text: str, markdown: bool = False) -> None:
    """Print output, optionally rendered as markdown."""
    if markdown and not console.no_color:
        console.print(Markdown(text))
    else:
        console.print(text)


def print_error(console: Console, message: str) -> None:
    """Print an error message."""
    if console.no_color:
        console.print(f"Error: {message}")
    else:
        console.print(f"[red]Error: {message}[/red]")


def check_dependency(executable: str, console: Console) -> bool:
    """Check if an executable exists in PATH."""
    if shutil.which(executable) is None:
        console.print(
            f"[red]Error: '{executable}' not found. Please install {executable} and ensure it's in your PATH.[/red]"
        )
        return False
    return True


def check_claude_cli(console: Console) -> bool:
    """Check if Claude Code CLI is installed and working."""
    if shutil.which("claude") is None:
        console.print(
            "[red]Error: Claude Code CLI not found.[/red]\n[yellow]Install it from https://claude.ai/download[/yellow]"
        )
        return False

    try:
        result = subprocess.run(
            ["claude", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            console.print(
                "[red]Error: Claude Code CLI failed to execute.[/red]\n"
                "[yellow]Try reinstalling from https://claude.ai/download[/yellow]"
            )
            return False
    except subprocess.TimeoutExpired:
        console.print(
            "[red]Error: Claude Code CLI timed out.[/red]\n"
            "[yellow]The CLI may be hanging. Try running 'claude --version' manually.[/yellow]"
        )
        return False
    except FileNotFoundError:
        console.print(
            "[red]Error: Claude Code CLI not found.[/red]\n[yellow]Install it from https://claude.ai/download[/yellow]"
        )
        return False

    has_api_key = os.environ.get("ANTHROPIC_API_KEY") is not None
    credentials_file = Path.home() / ".claude" / ".credentials.json"
    has_credentials_file = credentials_file.exists()

    if not has_api_key and not has_credentials_file:
        console.print(
            "[red]Error: Claude Code CLI is not authenticated.[/red]\n"
            "[yellow]Run 'claude' and sign in to authenticate, "
            "or set the ANTHROPIC_API_KEY environment variable.[/yellow]"
        )
        return False

    return True


def check_version_compatibility(console: Console) -> None:
    """Check and warn about CLI version compatibility."""
    cli_version = None

    try:
        result = subprocess.run(
            ["claude", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            version_output = result.stdout.strip()
            version_match = re.search(r"(\d+\.\d+\.\d+)", version_output)
            if version_match:
                cli_version = version_match.group(1)
    except Exception:
        pass

    if not cli_version:
        console.print(
            "[yellow]Warning: Could not determine Claude Code CLI version. "
            "Ensure you have the latest version installed.[/yellow]"
        )


def get_precommit_skip_env() -> dict[str, str]:
    """Return environment overrides to skip all pre-commit hooks.

    Uses SKIP_PRECOMMIT as a single toggle. When set to a truthy value, this
    reads .pre-commit-config.yaml to build a comma-separated SKIP list.
    """

    def is_truthy_env(value: str | None) -> bool:
        if value is None:
            return False
        normalized = value.strip().lower()
        if not normalized:
            return False
        return normalized not in {"0", "false", "no", "off", "n"}

    if not is_truthy_env(os.environ.get("SKIP_PRECOMMIT")):
        return {}

    fallback_hook_ids = [
        "ruff-format",
        "ruff",
        "shfmt",
        "shellcheck",
        "chezmoi-verify",
        "validate-python-version",
    ]

    def find_repo_root() -> Path | None:
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if result.returncode == 0:
                root = result.stdout.strip()
                if root:
                    return Path(root)
        except Exception:
            pass

        cwd = Path.cwd()
        for parent in (cwd, *cwd.parents):
            if (parent / ".pre-commit-config.yaml").exists():
                return parent
        return None

    def parse_hook_ids(config_text: str) -> list[str]:
        hook_ids: list[str] = []
        seen: set[str] = set()
        for line in config_text.splitlines():
            match = re.match(r"^\s*-\s*id:\s*([^\s#]+)", line)
            if not match:
                continue
            hook_id = match.group(1).strip().strip("\"'")
            if hook_id and hook_id not in seen:
                seen.add(hook_id)
                hook_ids.append(hook_id)
        return hook_ids

    repo_root = find_repo_root()
    if not repo_root:
        return {"SKIP": ",".join(fallback_hook_ids)}

    config_path = repo_root / ".pre-commit-config.yaml"
    try:
        with open(config_path, encoding="utf-8") as f:
            config_text = f.read()
        hook_ids = parse_hook_ids(config_text)
    except Exception:
        hook_ids = []

    if not hook_ids:
        hook_ids = fallback_hook_ids

    return {"SKIP": ",".join(hook_ids)}
