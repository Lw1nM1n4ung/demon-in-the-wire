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

_json_mode: bool = False


@app.callback()
def scans_callback(
    json_output: bool = typer.Option(
        False, "--json", help="Machine-readable JSON output"
    ),
) -> None:
    global _json_mode
    _json_mode = json_output


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
        if check_json_flag(json_output=_json_mode):
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
        if check_json_flag(json_output=_json_mode):
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
        if check_json_flag(json_output=_json_mode):
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
        if check_json_flag(json_output=_json_mode):
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
        if check_json_flag(json_output=_json_mode):
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


@app.command("create")
def create_scan(
    target: str = typer.Argument(..., help="Target IP, CIDR, or hostname"),
    policy: str = typer.Option("", "--policy", help="Policy name"),
    title: str = typer.Option("", "--title", help="Scan title"),
) -> None:
    """Create and queue a new portal-managed scan."""
    client = get_client()
    body: dict = {"target": target}
    if policy:
        body["policy"] = policy
    if title:
        body["title"] = title
    try:
        resp = client.post("/scans/", json=body)
        resp.raise_for_status()
        data = resp.json()
        console.print(f"[bold green]Scan created:[/] {data.get('id', '?')}")
        console.print(f"  Target: {target}")
        console.print(f"  Status: {data.get('status', '?')}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("cancel")
def cancel_scan(
    scan_id: str = typer.Argument(..., help="Scan UUID"),
) -> None:
    """Cancel a running or queued scan."""
    client = get_client()
    try:
        resp = client.post(f"/scans/{scan_id}/cancel/")
        resp.raise_for_status()
        console.print(f"[bold green]Scan cancelled:[/] {scan_id[:8]}...")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("clone")
def clone_scan(
    scan_id: str = typer.Argument(..., help="Scan UUID to clone"),
    target: str = typer.Option("", "--target", help="New target"),
) -> None:
    """Clone a scan (optionally with a new target)."""
    client = get_client()
    body: dict = {}
    if target:
        body["target"] = target
    try:
        resp = client.post(f"/scans/{scan_id}/clone/", json=body)
        resp.raise_for_status()
        data = resp.json()
        console.print(f"[bold green]Scan cloned:[/] {data.get('id', '?')}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("run")
def run_scan(
    scan_id: str = typer.Argument(..., help="Scan UUID"),
) -> None:
    """Run a queued scan immediately."""
    client = get_client()
    try:
        resp = client.post(f"/scans/{scan_id}/run/")
        resp.raise_for_status()
        console.print(f"[bold green]Scan started:[/] {scan_id[:8]}...")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
