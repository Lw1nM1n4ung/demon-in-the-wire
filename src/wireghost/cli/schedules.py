"""wireghost schedules — CRUD for scheduled scans."""

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

app = typer.Typer(name="schedules", help="Manage scan schedules")


@app.command("list")
def list_schedules() -> None:
    """List scheduled scans."""
    client = get_client()
    try:
        resp = client.get("/schedules/")
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "Scheduled Scans",
            [
                ("id", "ID"),
                ("name", "Name"),
                ("target", "Target"),
                ("cron", "Cron"),
                ("enabled", "Enabled"),
                ("next_run", "Next Run"),
            ],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("show")
def show_schedule(
    schedule_id: str = typer.Argument(..., help="Schedule UUID"),
) -> None:
    """Show schedule details."""
    client = get_client()
    try:
        resp = client.get(f"/schedules/{schedule_id}/")
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        echo_keyvalue(
            [
                ("ID:", data.get("id")),
                ("Name:", data.get("name", "—")),
                ("Target:", data.get("target", "—")),
                ("Cron:", data.get("cron", "—")),
                ("Policy:", data.get("policy", "—")),
                ("Enabled:", str(data.get("enabled", False))),
                ("Next run:", data.get("next_run", "—")),
                ("Last run:", data.get("last_run", "—")),
            ]
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("create")
def create_schedule(
    name: str = typer.Option(..., "--name", help="Schedule name"),
    target: str = typer.Option(..., "--target", help="Scan target"),
    cron: str = typer.Option(..., "--cron", help="Cron expression (e.g. '0 2 * * *')"),
    policy: str = typer.Option("", "--policy", help="Policy name"),
    title: str = typer.Option("", "--title", help="Scan title"),
) -> None:
    """Create a new scheduled scan."""
    client = get_client()
    body: dict = {"name": name, "target": target, "cron": cron}
    if policy:
        body["policy"] = policy
    if title:
        body["title"] = title
    try:
        resp = client.post("/schedules/", json=body)
        resp.raise_for_status()
        data = resp.json()
        console.print(f"[bold green]Schedule created:[/] {data.get('id', '?')}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("update")
def update_schedule(
    schedule_id: str = typer.Argument(..., help="Schedule UUID"),
    name: str = typer.Option("", "--name", help="New name"),
    target: str = typer.Option("", "--target", help="New target"),
    cron: str = typer.Option("", "--cron", help="New cron expression"),
) -> None:
    """Update a scheduled scan."""
    client = get_client()
    body: dict = {}
    if name:
        body["name"] = name
    if target:
        body["target"] = target
    if cron:
        body["cron"] = cron
    try:
        resp = client.patch(f"/schedules/{schedule_id}/", json=body)
        resp.raise_for_status()
        console.print(f"[bold green]Schedule updated:[/] {schedule_id[:8]}...")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("delete")
def delete_schedule(
    schedule_id: str = typer.Argument(..., help="Schedule UUID"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    """Delete a scheduled scan."""
    if not force:
        confirm = typer.confirm(f"Delete schedule {schedule_id}?")
        if not confirm:
            raise typer.Exit()
    client = get_client()
    try:
        resp = client.delete(f"/schedules/{schedule_id}/")
        resp.raise_for_status()
        console.print(f"[bold green]Schedule deleted:[/] {schedule_id[:8]}...")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("toggle")
def toggle_schedule(
    schedule_id: str = typer.Argument(..., help="Schedule UUID"),
) -> None:
    """Toggle a schedule on/off."""
    client = get_client()
    try:
        resp = client.post(f"/schedules/{schedule_id}/toggle/")
        resp.raise_for_status()
        data = resp.json()
        state = "enabled" if data.get("enabled") else "disabled"
        console.print(f"[bold green]Schedule {schedule_id[:8]}... {state}[/]")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
