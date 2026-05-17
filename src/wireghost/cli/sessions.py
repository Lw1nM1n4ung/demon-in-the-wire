"""wireghost sessions — session management."""
from __future__ import annotations

import typer

from wireghost.cli.client import get_client
from wireghost.cli.output import (
    check_json_flag,
    console,
    echo_json,
    echo_table,
)

app = typer.Typer(name="sessions", help="Session management")


@app.command("list")
def list_sessions() -> None:
    """List active sessions."""
    client = get_client()
    try:
        resp = client.get("/sessions/")
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "Active Sessions",
            [("session_key", "Key"), ("user", "User"), ("ip", "IP"),
             ("last_activity", "Last Activity")],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("revoke")
def revoke_session(
    session_key: str = typer.Argument(..., help="Session key"),
) -> None:
    """Revoke a specific session."""
    client = get_client()
    try:
        resp = client.post("/sessions/revoke/", json={"session_key": session_key})
        resp.raise_for_status()
        console.print(f"[bold green]Session revoked:[/] {session_key[:16]}...")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("revoke-all")
def revoke_all_sessions(
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    """Revoke all sessions except current."""
    if not force:
        confirm = typer.confirm("Revoke all other sessions?")
        if not confirm:
            raise typer.Exit()
    client = get_client()
    try:
        resp = client.post("/sessions/revoke-all/")
        resp.raise_for_status()
        console.print("[bold green]All other sessions revoked[/]")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
