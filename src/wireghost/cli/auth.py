"""wireghost auth — login, logout, whoami."""

from __future__ import annotations

import typer
from rich.console import Console

from wireghost.cli.client import get_client

app = typer.Typer(name="auth", help="Authentication")
console = Console(stderr=True)


@app.command()
def login(
    portal_url: str = typer.Option("", "--portal", "-p", help="Portal URL (default: prompts)"),
    username: str = typer.Option("", "--username", "-u", help="Username"),
    password: str = typer.Option("", "--password", "-P", help="Password (warning: shell history)"),
    mfa_code: str = typer.Option("", "--mfa", help="MFA code if required"),
) -> None:
    """Login to a Wire_Ghost portal (interactive)."""
    client = get_client()

    if not portal_url:
        portal_url = typer.prompt("Portal URL", default="https://localhost:18443")
        client.base_url = portal_url.rstrip("/")
    if not username:
        username = typer.prompt("Username")
    if not password:
        import getpass

        password = getpass.getpass("Password: ")

    try:
        result = client.login(username, password, mfa_code or None)
        user = result.get("user", result)
        console.print(
            f"[bold green]Logged in as[/] {user.get('username', username)} ({user.get('role', '?')})"
        )
        console.print(f"Portal: {client.base_url}")
    except Exception as e:
        console.print(f"[bold red]Login failed:[/] {e}")
        raise typer.Exit(code=1)


@app.command()
def logout() -> None:
    """Revoke cached token and delete session cache."""
    client = get_client()
    try:
        client.logout()
        console.print("[bold green]Logged out.[/]")
    except Exception as e:
        console.print(f"[bold yellow]Warning:[/] {e}")
    console.print("Run [bold]wireghost login[/] to authenticate again.")


@app.command()
def whoami() -> None:
    """Show current user, role, and session validity."""
    client = get_client()
    try:
        info = client.whoami()
        console.print(f"Username:   [bold]{info.get('username', '?')}[/]")
        console.print(f"Role:       {info.get('role', '?')}")
        console.print(f"Email:      {info.get('email', chr(0x2014))}")
        console.print(f"Portal:     {client.base_url}")
    except Exception as e:
        console.print(f"[bold red]Not authenticated:[/] {e}")
        console.print("Run [bold]wireghost login[/] to authenticate.")
        raise typer.Exit(code=1)
