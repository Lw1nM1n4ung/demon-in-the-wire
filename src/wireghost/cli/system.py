"""wireghost system — system operations."""

from __future__ import annotations

import typer

from wireghost.cli.client import get_client
from wireghost.cli.output import (
    check_json_flag,
    console,
    echo_json,
    echo_keyvalue,
    echo_table,
)

app = typer.Typer(name="system", help="System operations")


@app.command("stats")
def system_stats() -> None:
    """Show real-time system resource usage."""
    client = get_client()
    try:
        resp = client.get("/system-stats/")
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        echo_keyvalue(
            [
                ("CPU %:", str(data.get("cpu_percent", "—"))),
                ("Memory:", data.get("memory", "—")),
                ("Disk:", data.get("disk", "—")),
                ("Uptime:", data.get("uptime", "—")),
            ]
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("processes")
def system_processes() -> None:
    """Show container processes."""
    client = get_client()
    try:
        resp = client.get("/system-processes/")
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "Container Processes",
            [
                ("name", "Name"),
                ("pid", "PID"),
                ("cpu", "CPU%"),
                ("mem", "Mem%"),
                ("status", "Status"),
            ],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("tools")
def system_tools() -> None:
    """Show installed tool versions."""
    client = get_client()
    try:
        resp = client.get("/tools-health/")
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("tools", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "Security Tools",
            [("name", "Tool"), ("version", "Version"), ("status", "Status")],
            results if isinstance(results, list) else list(results.items()),
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("audit")
def system_audit(
    limit: int = typer.Option(50, "--limit", "-n", help="Max results"),
) -> None:
    """Show audit log."""
    client = get_client()
    try:
        resp = client.get("/audit-log/", params={"limit": limit})
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "Audit Log",
            [("timestamp", "Time"), ("user", "User"), ("action", "Action"), ("detail", "Detail")],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("update")
def system_update(
    tools: bool = typer.Option(False, "--tools", help="Update security tools"),
    feeds: bool = typer.Option(False, "--feeds", help="Update vulnerability feeds"),
    self_update: bool = typer.Option(
        False, "--self", help="Update wireghost itself (git pull + pip install)"
    ),
    all_update: bool = typer.Option(
        False, "--all", help="Update everything: tools, feeds, and wireghost (local)"
    ),
) -> None:
    """Check for or apply updates."""
    # --all runs everything locally via updater.py
    if all_update:
        try:
            from wireghost.utils.updater import update_all

            update_all()
        except Exception as e:
            console.print(f"[bold red]Error:[/] {e}")
            raise typer.Exit(code=1)
        return

    # --self runs self-update locally
    if self_update:
        try:
            from wireghost.utils.updater import update_self

            update_self()
        except Exception as e:
            console.print(f"[bold red]Error:[/] {e}")
            raise typer.Exit(code=1)
        if not tools and not feeds:
            return

    # Check mode (no flags)
    if not tools and not feeds and not self_update:
        client = get_client()
        try:
            resp = client.get("/update-check/")
            resp.raise_for_status()
            data = resp.json()
            if check_json_flag():
                echo_json(data)
                return
            echo_keyvalue(
                [
                    ("Current version:", data.get("current", "—")),
                    ("Latest version:", data.get("latest", "—")),
                    ("Update available:", str(data.get("update_available", False))),
                ]
            )
        except Exception as e:
            console.print(f"[bold red]Error:[/] {e}")
            raise typer.Exit(code=1)
        return

    # API-based tools/feeds update
    client = get_client()
    try:
        if tools:
            resp = client.post("/update/apply/", json={"type": "tools"})
            resp.raise_for_status()
            console.print("[bold green]Tools update triggered[/]")
        if feeds:
            resp = client.post("/update/feeds/")
            resp.raise_for_status()
            console.print("[bold green]Feeds update triggered[/]")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("feeds")
def system_feeds() -> None:
    """Show vulnerability feed status."""
    client = get_client()
    try:
        resp = client.get("/update/feeds/")
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        echo_keyvalue(
            [
                ("Nuclei templates:", data.get("nuclei_templates", "—")),
                ("SearchSploit:", data.get("searchsploit_db", "—")),
                ("MSF metadata:", data.get("msf_metadata", "—")),
            ]
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
