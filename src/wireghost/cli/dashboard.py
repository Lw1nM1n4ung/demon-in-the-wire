"""wireghost dashboard — stats and screenshots."""

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

app = typer.Typer(name="dashboard", help="Dashboard stats and screenshots")


@app.command("stats")
def dashboard_stats() -> None:
    """Show dashboard statistics."""
    client = get_client()
    try:
        resp = client.get("/dashboard/")
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        echo_keyvalue(
            [
                ("Total scans:", str(data.get("total_scans", 0))),
                ("Running scans:", str(data.get("running_scans", 0))),
                ("Total hosts:", str(data.get("total_hosts", 0))),
                ("Total findings:", str(data.get("total_findings", 0))),
                ("Critical:", str(data.get("critical_findings", 0))),
                ("High:", str(data.get("high_findings", 0))),
                ("Medium:", str(data.get("medium_findings", 0))),
                ("Low:", str(data.get("low_findings", 0))),
            ]
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("screenshots")
def dashboard_screenshots(
    scan_id: str = typer.Option("", "--scan", help="Filter by scan ID"),
    limit: int = typer.Option(20, "--limit", "-n", help="Max results"),
) -> None:
    """List dashboard screenshots."""
    client = get_client()
    params: dict = {"limit": limit}
    if scan_id:
        params["scan"] = scan_id
    try:
        resp = client.get("/dashboard/screenshots/", params=params)
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "Screenshots",
            [("id", "ID"), ("url", "URL"), ("host", "Host"), ("port", "Port"), ("title", "Title")],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
