"""wireghost notify — notification configuration."""
from __future__ import annotations

import typer

from wireghost.cli.client import get_client
from wireghost.cli.output import check_json_flag, console, echo_json, echo_keyvalue

app = typer.Typer(name="notify", help="Notification configuration")


@app.command("config")
def notify_config() -> None:
    """Show notification configuration."""
    client = get_client()
    try:
        resp = client.get("/notifications/config/")
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        token = data.get("telegram_bot_token", "")
        echo_keyvalue([
            ("Telegram bot:", token[:20] + "..." if token else "—"),
            ("Enabled:", str(data.get("enabled", False))),
            ("On findings:", str(data.get("on_finding", False))),
            ("On scan complete:", str(data.get("on_scan_complete", False))),
        ])
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("test")
def notify_test(
    channel: str = typer.Option(
        "telegram", "--channel", help="telegram or email"
    ),
) -> None:
    """Send a test notification."""
    client = get_client()
    try:
        resp = client.post("/notifications/test/", json={"channel": channel})
        resp.raise_for_status()
        console.print(f"[bold green]Test notification sent via {channel}[/]")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
