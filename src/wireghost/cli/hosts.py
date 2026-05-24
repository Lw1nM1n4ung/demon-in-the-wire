"""wireghost hosts — host information."""

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

app = typer.Typer(name="hosts", help="Host information")


@app.command("list")
def list_hosts(
    scan_id: str = typer.Option("", "--scan", help="Filter by scan ID"),
    limit: int = typer.Option(20, "--limit", "-n", help="Max results"),
) -> None:
    """List hosts."""
    client = get_client()
    params: dict = {"limit": limit}
    if scan_id:
        params["scan"] = scan_id
    try:
        resp = client.get("/hosts/", params=params)
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "Hosts",
            [
                ("ip", "IP"),
                ("hostname", "Hostname"),
                ("os", "OS"),
                ("open_ports", "Ports"),
                ("status", "Status"),
            ],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("show")
def show_host(
    ip: str = typer.Argument(..., help="Host IP address"),
    scan_id: str = typer.Option("", "--scan", help="Scan ID context"),
) -> None:
    """Show host details."""
    client = get_client()
    params: dict = {}
    if scan_id:
        params["scan"] = scan_id
    try:
        resp = client.get(f"/hosts/{ip}/", params=params)
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        echo_keyvalue(
            [
                ("IP:", data.get("ip")),
                ("Hostname:", data.get("hostname", "—")),
                ("OS:", data.get("os", "—")),
                ("Status:", data.get("status", "—")),
                ("Open Ports:", str(data.get("open_ports", 0))),
                ("MAC:", data.get("mac", "—")),
            ]
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("topology")
def host_topology(
    scan_id: str = typer.Argument(..., help="Scan ID"),
) -> None:
    """Show network topology for a scan."""
    client = get_client()
    try:
        resp = client.get(f"/scans/{scan_id}/topology/")
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        console.print(f"[bold]Topology for {scan_id[:8]}...[/]")
        console.print(f"  Nodes: {len(data.get('nodes', []))}")
        console.print(f"  Edges: {len(data.get('edges', []))}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
