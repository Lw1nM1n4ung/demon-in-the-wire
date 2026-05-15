"""wireghost scans — portal-managed scan operations."""
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

app = typer.Typer(name="scans", help="Manage portal scans")


@app.callback()
def scans_callback(
    json_output: bool = typer.Option(
        False, "--json", help="Machine-readable JSON output"
    ),
) -> None:
    del json_output  # handled by check_json_flag() via sys.argv


@app.command("list")
def list_scans(
    limit: int = typer.Option(20, "--limit", "-n", help="Max results"),
    status: str = typer.Option(
        "", "--status", help="Filter: running, completed, cancelled, queued"
    ),
) -> None:
    """List portal scans."""
    client = get_client()
    params: dict = {"limit": limit}
    if status:
        params["status"] = status

    try:
        resp = client.get("/scans/", params=params)
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "Portal Scans",
            [("id", "ID"), ("target", "Target"), ("status", "Status"),
             ("finding_count", "Findings"), ("created_at", "Created")],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("show")
def show_scan(
    scan_id: str = typer.Argument(..., help="Scan UUID"),
) -> None:
    """Show scan details."""
    client = get_client()
    try:
        resp = client.get(f"/scans/{scan_id}/")
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        echo_keyvalue([
            ("ID:", data.get("id")),
            ("Target:", data.get("target")),
            ("Status:", data.get("status")),
            ("Title:", data.get("title", "—")),
            ("Policy:", data.get("policy", "—")),
            ("Findings:", str(data.get("finding_count", 0))),
            ("Hosts:", str(data.get("host_count", 0))),
            ("Created:", data.get("created_at", "—")),
            ("Started:", data.get("started_at", "—")),
            ("Completed:", data.get("completed_at", "—")),
        ])
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("findings")
def scan_findings(
    scan_id: str = typer.Argument(..., help="Scan UUID"),
    severity: str = typer.Option(
        "", "--severity", help="Filter: critical, high, medium, low, info"
    ),
    source: str = typer.Option(
        "", "--source", help="Filter: nuclei, nmap_vuln, msf_scan, ..."
    ),
) -> None:
    """List findings for a scan."""
    client = get_client()
    params: dict = {}
    if severity:
        params["severity"] = severity
    if source:
        params["source"] = source
    try:
        resp = client.get(f"/scans/{scan_id}/findings/", params=params)
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            f"Findings for {scan_id[:8]}...",
            [("id", "ID"), ("severity", "Severity"), ("source", "Source"),
             ("title", "Title"), ("host", "Host"), ("port", "Port")],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("hosts")
def scan_hosts(
    scan_id: str = typer.Argument(..., help="Scan UUID"),
) -> None:
    """List hosts for a scan."""
    client = get_client()
    try:
        resp = client.get(f"/scans/{scan_id}/hosts/")
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            f"Hosts for {scan_id[:8]}...",
            [("ip", "IP"), ("hostname", "Hostname"), ("os", "OS"),
             ("open_ports", "Open Ports"), ("status", "Status")],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("topology")
def scan_topology(
    scan_id: str = typer.Argument(..., help="Scan UUID"),
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
        nodes = data.get("nodes", [])
        edges = data.get("edges", [])
        console.print(f"  Nodes: {len(nodes)}")
        console.print(f"  Edges: {len(edges)}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
