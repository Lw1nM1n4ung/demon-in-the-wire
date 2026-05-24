"""wireghost report — report generation and download."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer

from wireghost.cli.client import get_client
from wireghost.cli.output import check_json_flag, console, echo_json

app = typer.Typer(name="report", help="Report generation and download")


@app.command("generate")
def generate_report(
    scan_dir: Path = typer.Argument(..., help="Path to scan output directory"),
    output_dir: Optional[Path] = typer.Option(None, "--output", "-o", help="Output directory"),
    formats: str = typer.Option(
        "html,docx,xlsx", "--formats", "-f", help="Comma-separated formats"
    ),
    title: str = typer.Option("Security Assessment Summary Report", "--title", help="Report title"),
) -> None:
    """Generate reports from a local scan directory."""
    cmd = [sys.executable, "-m", "wireghost", "report", str(scan_dir)]
    if output_dir:
        cmd.extend(["-o", str(output_dir)])
    cmd.extend(["-f", formats])
    cmd.extend(["--title", title])

    console.print(f"[dim]Running: {' '.join(cmd)}[/]")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        console.print("[bold red]Report generation failed[/]")
        raise typer.Exit(code=1)


@app.command("download")
def download_report(
    scan_id: str = typer.Argument(..., help="Portal scan UUID"),
    format: str = typer.Option("docx", "--format", help="docx, html, or xlsx"),
    output_dir: Optional[Path] = typer.Option(None, "--output", "-o", help="Output directory"),
) -> None:
    """Download a report from a portal-managed scan."""
    client = get_client()
    try:
        resp = client.get(f"/reports/{scan_id}/download/", params={"format": format})
        resp.raise_for_status()
        ext = {"docx": "docx", "html": "html", "xlsx": "xlsx"}.get(format, format)
        out = output_dir or Path(".")
        out.mkdir(parents=True, exist_ok=True)
        outfile = out / f"report_{scan_id[:8]}.{ext}"
        outfile.write_bytes(resp.content)
        console.print(f"[bold green]Report saved:[/] {outfile}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("config")
def report_config() -> None:
    """Show report configuration."""
    client = get_client()
    try:
        resp = client.get("/report-config/")
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        console.print(f"Company: {data.get('company', '—')}")
        console.print(f"Logo:    {data.get('logo_url', '—')}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("logo")
def report_logo(
    image_path: Path = typer.Argument(..., help="Path to logo image file"),
) -> None:
    """Upload a report logo."""
    client = get_client()
    try:
        with open(image_path, "rb") as f:
            resp = client.post(
                "/report-config/logo/",
                files={"logo": (image_path.name, f, "image/png")},
            )
        resp.raise_for_status()
        console.print(f"[bold green]Logo uploaded:[/] {image_path}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
