"""wireghost findings — view and triage findings."""
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

app = typer.Typer(name="findings", help="View and triage findings")


@app.command("list")
def list_findings(
    scan_id: str = typer.Option("", "--scan", help="Filter by scan ID"),
    severity: str = typer.Option(
        "", "--severity", help="Filter: critical, high, medium, low, info"
    ),
    source: str = typer.Option(
        "", "--source", help="Filter: nuclei, nmap_vuln, msf_scan, ..."
    ),
    search: str = typer.Option("", "--search", help="Full-text search"),
    limit: int = typer.Option(20, "--limit", "-n", help="Max results"),
) -> None:
    """List findings."""
    client = get_client()
    params: dict = {"limit": limit}
    if scan_id:
        params["scan"] = scan_id
    if severity:
        params["severity"] = severity
    if source:
        params["source"] = source
    if search:
        params["search"] = search
    try:
        resp = client.get("/findings/", params=params)
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "Findings",
            [("id", "ID"), ("severity", "Severity"), ("source", "Source"),
             ("title", "Title"), ("host", "Host"), ("port", "Port")],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("show")
def show_finding(
    finding_id: str = typer.Argument(..., help="Finding UUID"),
) -> None:
    """Show finding details."""
    client = get_client()
    try:
        resp = client.get(f"/findings/{finding_id}/")
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        echo_keyvalue([
            ("ID:", data.get("id")),
            ("Title:", data.get("title", "—")),
            ("Severity:", str(data.get("severity", "—"))),
            ("Source:", data.get("source", "—")),
            ("Host:", data.get("host", "—")),
            ("Port:", str(data.get("port", ""))),
            ("CVE:", data.get("cve", "—")),
            ("Description:", data.get("description", "—")),
            ("Template:", data.get("template_id", "—")),
            ("False Positive:", str(data.get("false_positive", False))),
        ])
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("toggle")
def toggle_finding(
    finding_id: str = typer.Argument(..., help="Finding UUID"),
) -> None:
    """Toggle finding false-positive status."""
    client = get_client()
    try:
        resp = client.patch(f"/findings/{finding_id}/", json={"toggle_fp": True})
        resp.raise_for_status()
        data = resp.json()
        status = "flagged as false positive" if data.get("false_positive") else "unflagged"
        console.print(f"[bold green]Finding {finding_id[:8]}... {status}[/]")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
