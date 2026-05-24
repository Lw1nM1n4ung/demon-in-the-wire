"""wireghost policies — CRUD for scan policies."""

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

app = typer.Typer(name="policies", help="Manage scan policies")


@app.command("list")
def list_policies() -> None:
    """List scan policies."""
    client = get_client()
    try:
        resp = client.get("/policies/")
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "Scan Policies",
            [
                ("id", "ID"),
                ("name", "Name"),
                ("type", "Type"),
                ("parallelism", "Parallelism"),
                ("created_at", "Created"),
            ],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("show")
def show_policy(
    policy_id: str = typer.Argument(..., help="Policy UUID"),
) -> None:
    """Show policy details."""
    client = get_client()
    try:
        resp = client.get(f"/policies/{policy_id}/")
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        echo_keyvalue(
            [
                ("ID:", data.get("id")),
                ("Name:", data.get("name", "—")),
                ("Type:", data.get("type", "—")),
                ("Description:", data.get("description", "—")),
                ("Parallelism:", str(data.get("parallelism", 10))),
                ("Timeout:", str(data.get("timeout", 3600))),
                ("Skip Nuclei:", str(data.get("skip_nuclei", False))),
                ("Skip Vuln:", str(data.get("skip_vuln", False))),
                ("Skip Screenshots:", str(data.get("skip_screenshots", False))),
            ]
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("create")
def create_policy(
    name: str = typer.Option(..., "--name", help="Policy name"),
    type: str = typer.Option("external", "--type", help="external, internal, or full"),
    description: str = typer.Option("", "--description", help="Description"),
    skip_nuclei: bool = typer.Option(False, "--skip-nuclei"),
    skip_vuln: bool = typer.Option(False, "--skip-vuln"),
    skip_screenshots: bool = typer.Option(False, "--skip-screenshots"),
    parallelism: int = typer.Option(10, "--parallelism", "-j"),
    timeout: int = typer.Option(3600, "--timeout", "-t"),
) -> None:
    """Create a new scan policy."""
    client = get_client()
    try:
        resp = client.post(
            "/policies/",
            json={
                "name": name,
                "type": type,
                "description": description,
                "skip_nuclei": skip_nuclei,
                "skip_vuln": skip_vuln,
                "skip_screenshots": skip_screenshots,
                "parallelism": parallelism,
                "timeout": timeout,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        console.print(f"[bold green]Policy created:[/] {data.get('id', '?')}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("update")
def update_policy(
    policy_id: str = typer.Argument(..., help="Policy UUID"),
    name: str = typer.Option("", "--name", help="New name"),
    description: str = typer.Option("", "--description", help="New description"),
    parallelism: int = typer.Option(0, "--parallelism", "-j", help="New parallelism"),
    timeout: int = typer.Option(0, "--timeout", "-t", help="New timeout"),
) -> None:
    """Update a scan policy."""
    client = get_client()
    body: dict = {}
    if name:
        body["name"] = name
    if description:
        body["description"] = description
    if parallelism:
        body["parallelism"] = parallelism
    if timeout:
        body["timeout"] = timeout
    try:
        resp = client.patch(f"/policies/{policy_id}/", json=body)
        resp.raise_for_status()
        console.print(f"[bold green]Policy updated:[/] {policy_id[:8]}...")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("delete")
def delete_policy(
    policy_id: str = typer.Argument(..., help="Policy UUID"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    """Delete a scan policy."""
    if not force:
        confirm = typer.confirm(f"Delete policy {policy_id}?")
        if not confirm:
            raise typer.Exit()
    client = get_client()
    try:
        resp = client.delete(f"/policies/{policy_id}/")
        resp.raise_for_status()
        console.print(f"[bold green]Policy deleted:[/] {policy_id[:8]}...")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("clone")
def clone_policy(
    policy_id: str = typer.Argument(..., help="Policy UUID to clone"),
    name: str = typer.Option("", "--name", help="New policy name"),
) -> None:
    """Clone a scan policy."""
    client = get_client()
    try:
        resp = client.post(f"/policies/{policy_id}/clone/", json={"name": name} if name else {})
        resp.raise_for_status()
        data = resp.json()
        console.print(f"[bold green]Policy cloned:[/] {data.get('id', '?')}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
