"""Lazy dependency import helpers."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

import click

if TYPE_CHECKING:
    from types import ModuleType


def require(module_name: str, command: str) -> ModuleType:
    """Import a module, raising a Click error if missing.

    Call this inside command function bodies, not at module level,
    so that ``devtool --help`` never triggers heavy imports.
    """
    try:
        return importlib.import_module(module_name)
    except ImportError:
        raise click.ClickException(
            f"'{command}' requires '{module_name}'.\nReinstall with: uv tool install -e . --force"
        ) from None
