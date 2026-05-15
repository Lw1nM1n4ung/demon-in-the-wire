"""Wire_Ghost CLI — thin dispatcher that mounts domain apps."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from wireghost import __version__

app = typer.Typer(
    name="wireghost",
    help="Wire_Ghost security scanning toolkit",
    no_args_is_help=True,
)
console = Console(stderr=True)


@app.callback(invoke_without_command=True)
def main(
    version: bool = typer.Option(
        False, "--version", "-V", help="Show version and exit"
    ),
) -> None:
    """Wire_Ghost — automated security scanning toolkit."""
    if version:
        typer.echo(f"wireghost {__version__}")
        raise typer.Exit()


# ── Config commands ───────────────────────────────────────────────────


@app.command("config")
def config_cmd(
    action: str = typer.Argument(
        "show", help="Action: 'show' to print config, 'init' to create wireghost.yml"
    ),
) -> None:
    """Show resolved config or initialize a wireghost.yml file."""
    if action == "init":
        _config_init()
    elif action == "show":
        _config_show()
    else:
        console.print(f"[bold red]Unknown action:[/] {action}")
        console.print("Use 'show' or 'init'")
        raise typer.Exit(code=1)


def _config_init() -> None:
    dest = Path("wireghost.yml")
    if dest.exists():
        console.print(
            "[bold yellow]wireghost.yml already exists.[/] "
            "Remove it first to re-initialize."
        )
        raise typer.Exit(code=1)

    example = Path(__file__).resolve().parent.parent.parent / "wireghost.example.yml"
    if not example.is_file():
        for candidate in [
            Path("wireghost.example.yml"),
            Path(__file__).resolve().parent.parent / "wireghost.example.yml",
        ]:
            if candidate.is_file():
                example = candidate
                break

    if example.is_file():
        shutil.copy2(example, dest)
        console.print(f"[bold green]Created[/] wireghost.yml from {example.name}")
    else:
        dest.write_text(
            "# Wire_Ghost configuration\n"
            "# target: \"192.168.1.0/24\"\n"
            "output_dir: \"./output\"\n"
            "parallelism: 10\n"
            "version_detect: true\n"
            "os_detect: true\n"
            "service_enum: true\n"
            "skip_nuclei: false\n"
            "skip_vuln: false\n"
            "skip_brute_force: false\n"
            "tool_timeout: 3600\n"
            "report_formats:\n"
            "  - html\n"
            "  - docx\n"
            "  - xlsx\n"
            'report_title: "Security Assessment Summary Report"\n'
            "verbose: false\n",
            encoding="utf-8",
        )
        console.print("[bold green]Created[/] wireghost.yml with defaults")


def _config_show() -> None:
    from wireghost.config import ScanConfig

    cfg = ScanConfig.load()
    table = Table(title="Wire_Ghost Configuration", show_header=True)
    table.add_column("Setting", style="bold")
    table.add_column("Value")

    table.add_row("target", cfg.target or "(not set)")
    table.add_row("output_dir", str(cfg.output_dir))
    table.add_row("parallelism", str(cfg.parallelism))
    table.add_row("version_detect", str(cfg.version_detect))
    table.add_row("os_detect", str(cfg.os_detect))
    table.add_row("service_enum", str(cfg.service_enum))
    table.add_row("skip_nuclei", str(cfg.skip_nuclei))
    table.add_row("skip_vuln", str(cfg.skip_vuln))
    table.add_row("tool_timeout", str(cfg.tool_timeout))
    table.add_row("report_formats", ", ".join(cfg.report_formats))
    table.add_row("report_title", cfg.report_title)
    table.add_row("verbose", str(cfg.verbose))

    console.print(table)


# ── Deprecation stubs (old commands, now under domain apps) ──────


@app.command("report", hidden=True)
def report_deprecated(
    scan_dir: str = typer.Argument(..., help="Scan directory"),
) -> None:
    """[DEPRECATED] Use 'wireghost report generate' instead."""
    console.print(
        "[bold yellow]Deprecated:[/] 'wireghost report' → use "
        "'wireghost report generate <scan-dir>'"
    )
    subprocess.run([sys.executable, "-m", "wireghost", "report", "generate", scan_dir])


@app.command("update", hidden=True)
def update_deprecated() -> None:
    """[DEPRECATED] Use 'wireghost system update' instead."""
    console.print(
        "[bold yellow]Deprecated:[/] 'wireghost update' → use "
        "'wireghost system update'"
    )


# ── Mount domain apps ─────────────────────────────────────────────────

from wireghost.cli.auth import app as auth_app
app.add_typer(auth_app, name="auth", help="Authentication")

from wireghost.cli.scan import app as scan_app
app.add_typer(scan_app, name="scan", help="Run a local scan pipeline")

from wireghost.cli.scans import app as scans_app
app.add_typer(scans_app, name="scans", help="Manage portal scans")

from wireghost.cli.hosts import app as hosts_app
app.add_typer(hosts_app, name="hosts", help="Host information")

from wireghost.cli.findings import app as findings_app
app.add_typer(findings_app, name="findings", help="View and triage findings")

from wireghost.cli.policies import app as policies_app
app.add_typer(policies_app, name="policies", help="Manage scan policies")

from wireghost.cli.schedules import app as schedules_app
app.add_typer(schedules_app, name="schedules", help="Manage scan schedules")

from wireghost.cli.exploits import app as exploits_app
app.add_typer(exploits_app, name="exploits", help="View exploit matches")

from wireghost.cli.users import app as users_app
app.add_typer(users_app, name="users", help="User management")

from wireghost.cli.tokens import app as tokens_app
app.add_typer(tokens_app, name="tokens", help="API token management")

from wireghost.cli.sessions import app as sessions_app
app.add_typer(sessions_app, name="sessions", help="Session management")

from wireghost.cli.system import app as system_app
app.add_typer(system_app, name="system", help="System operations")

from wireghost.cli.reports import app as reports_app
app.add_typer(reports_app, name="report", help="Report generation and download")

from wireghost.cli.notifications import app as notifications_app
app.add_typer(notifications_app, name="notify", help="Notification configuration")

from wireghost.cli.dashboard import app as dashboard_app
app.add_typer(dashboard_app, name="dashboard", help="Dashboard stats and screenshots")

from wireghost.cli.support import app as support_app
app.add_typer(support_app, name="support-bundle", help="Generate support diagnostic bundle")

from wireghost.cli.deploy import app as deploy_app
app.add_typer(deploy_app, name="deploy", help="Deploy to a remote host via SSH")
