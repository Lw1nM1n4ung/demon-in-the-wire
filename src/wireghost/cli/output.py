"""Shared output formatting helpers."""
from __future__ import annotations

import json as _json
import sys
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

console = Console(stderr=True)


def echo_json(data: Any) -> None:
    """Print data as JSON to stdout."""
    typer.echo(_json.dumps(data, default=str, indent=2))


def echo_table(
    title: str,
    columns: list[tuple[str, str]],  # (key, header)
    rows: list[dict],
) -> None:
    """Print a Rich table from a list of dicts."""
    if not sys.stdout.isatty():
        echo_json(rows)
        return

    table = Table(title=title, show_header=True, title_style="bold")
    for _, header in columns:
        table.add_column(header)
    for row in rows:
        table.add_row(*[str(row.get(k, "")) for k, _ in columns])
    console.print(table)


def echo_keyvalue(pairs: list[tuple[str, Any]]) -> None:
    """Print key-value pairs."""
    if not sys.stdout.isatty():
        echo_json(dict(pairs))
        return

    max_key = max(len(k) for k, _ in pairs) if pairs else 0
    for key, val in pairs:
        console.print(f"{key:<{max_key + 2}}{val}")


def check_json_flag(json_output: bool = False) -> bool:
    """Return True if --json output mode is active.

    Prefer the explicit *json_output* parameter (wired from an @app.callback()
    --json option).  Falls back to inspecting sys.argv so modules that haven't
    been updated yet still work.
    """
    return json_output or "--json" in sys.argv
