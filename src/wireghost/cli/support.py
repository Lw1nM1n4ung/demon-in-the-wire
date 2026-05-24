"""wireghost support-bundle — diagnostic bundle generation."""

from __future__ import annotations

import typer

from wireghost.cli.client import get_client
from wireghost.cli.output import console

app = typer.Typer(name="support-bundle", help="Generate support diagnostic bundle")


@app.callback(invoke_without_command=True)
def support_bundle(
    output: str = typer.Option("", "--output", "-o", help="Output path for bundle"),
) -> None:
    """Generate a support diagnostic bundle (Owner only)."""
    del output  # reserved for future local export
    client = get_client()
    try:
        console.print("[dim]Generating support bundle...[/]")
        resp = client.post("/support-bundle/")
        resp.raise_for_status()
        data = resp.json()
        bundle_path = data.get("path", "support_bundle.tar.gz")
        console.print(f"[bold green]Support bundle ready:[/] {bundle_path}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
