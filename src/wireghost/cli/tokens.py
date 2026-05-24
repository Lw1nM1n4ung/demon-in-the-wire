"""wireghost tokens — API token management."""

from __future__ import annotations

import typer

from wireghost.cli.client import get_client
from wireghost.cli.output import (
    check_json_flag,
    console,
    echo_json,
    echo_table,
)

app = typer.Typer(name="tokens", help="API token management")


@app.command("list")
def list_tokens() -> None:
    """List personal API tokens."""
    client = get_client()
    try:
        resp = client.get("/auth/tokens/")
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "API Tokens",
            [("id", "ID"), ("name", "Name"), ("last_used", "Last Used"), ("created_at", "Created")],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("create")
def create_token(
    name: str = typer.Option(..., "--name", help="Token description"),
) -> None:
    """Create a new personal API token."""
    client = get_client()
    try:
        resp = client.post("/auth/tokens/", json={"name": name})
        resp.raise_for_status()
        data = resp.json()
        token = data.get("token") or data.get("key", "")
        console.print(f"[bold green]Token created:[/] {data.get('name', name)}")
        if token:
            console.print("[bold]Token value (save this — it won't be shown again):[/]")
            console.print(token)
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("revoke")
def revoke_token(
    token_id: str = typer.Argument(..., help="Token UUID"),
) -> None:
    """Revoke a personal API token."""
    client = get_client()
    try:
        resp = client.post(f"/auth/tokens/{token_id}/revoke/")
        resp.raise_for_status()
        console.print(f"[bold green]Token revoked:[/] {token_id[:8]}...")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
