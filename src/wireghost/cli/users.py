"""wireghost users — user management."""
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

app = typer.Typer(name="users", help="User management")


@app.command("list")
def list_users() -> None:
    """List users."""
    client = get_client()
    try:
        resp = client.get("/auth/users/")
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "Users",
            [("id", "ID"), ("username", "Username"), ("role", "Role"),
             ("email", "Email"), ("status", "Status"), ("last_login", "Last Login")],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("show")
def show_user(
    user_id: str = typer.Argument(..., help="User UUID or username"),
) -> None:
    """Show user details."""
    client = get_client()
    try:
        resp = client.get(f"/auth/users/{user_id}/")
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        echo_keyvalue([
            ("ID:", data.get("id")),
            ("Username:", data.get("username", "—")),
            ("Name:", data.get("name", "—")),
            ("Role:", data.get("role", "—")),
            ("Email:", data.get("email", "—")),
            ("Status:", data.get("status", "—")),
            ("Last login:", data.get("last_login", "—")),
            ("Created:", data.get("created_at", "—")),
        ])
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("create")
def create_user(
    username: str = typer.Option(..., "--username", help="Username"),
    role: str = typer.Option(..., "--role", help="owner, engineer, or viewer"),
    email: str = typer.Option("", "--email", help="Email address"),
    password_prompt: bool = typer.Option(
        False, "--password-prompt", help="Interactive password input"
    ),
) -> None:
    """Create a new user."""
    client = get_client()
    import getpass
    password = getpass.getpass("Password: ")

    try:
        resp = client.post("/auth/users/create/", json={
            "username": username, "role": role, "email": email, "password": password,
        })
        resp.raise_for_status()
        data = resp.json()
        console.print(f"[bold green]User created:[/] {data.get('username', '?')}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("update")
def update_user(
    user_id: str = typer.Argument(..., help="User UUID"),
    username: str = typer.Option("", "--username", help="New username"),
    role: str = typer.Option("", "--role", help="New role"),
    email: str = typer.Option("", "--email", help="New email"),
) -> None:
    """Update a user."""
    client = get_client()
    body: dict = {}
    if username:
        body["username"] = username
    if role:
        body["role"] = role
    if email:
        body["email"] = email
    try:
        resp = client.put(f"/auth/users/{user_id}/", json=body)
        resp.raise_for_status()
        console.print(f"[bold green]User updated:[/] {user_id[:8]}...")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("delete")
def delete_user(
    user_id: str = typer.Argument(..., help="User UUID"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    """Delete a user."""
    if not force:
        confirm = typer.confirm(f"Delete user {user_id}?")
        if not confirm:
            raise typer.Exit()
    client = get_client()
    try:
        resp = client.delete(f"/auth/users/{user_id}/delete/")
        resp.raise_for_status()
        console.print(f"[bold green]User deleted:[/] {user_id[:8]}...")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("reset-password")
def reset_password(
    username: str = typer.Argument(..., help="Username to reset password for"),
) -> None:
    """Reset a user's password (interactive)."""
    import getpass

    new_password = getpass.getpass(f"New password for {username}: ")
    confirm = getpass.getpass("Confirm password: ")
    if new_password != confirm:
        console.print("[bold red]Passwords do not match[/]")
        raise typer.Exit(code=1)

    client = get_client()
    try:
        resp = client.post(f"/auth/users/{username}/reset-password/", json={
            "password": new_password,
        })
        if resp.status_code == 404:
            console.print(
                "[bold yellow]API endpoint not available.[/] "
                "Use [bold]wg-ctl reset-password <username>[/] from the server."
            )
            raise typer.Exit(code=1)
        resp.raise_for_status()
        console.print(f"[bold green]Password reset for {username}[/]")
    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
