"""Wire_Ghost CLI — thin dispatcher that mounts domain apps."""
from __future__ import annotations

import asyncio
import shutil
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


# ── Local scan pipeline (the core command) ────────────────────────────


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target IP, CIDR range, or hostname"),
    output_dir: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output directory (default: ./output)"
    ),
    parallelism: int = typer.Option(
        10, "--parallelism", "-j", help="Max concurrent host scans"
    ),
    skip_nuclei: bool = typer.Option(
        False, "--skip-nuclei", help="Skip nuclei web scanning"
    ),
    skip_vuln: bool = typer.Option(
        False, "--skip-vuln", help="Skip nmap vuln scanning"
    ),
    timeout: float = typer.Option(
        3600.0, "--timeout", "-t", help="Per-tool timeout in seconds"
    ),
    report_formats: Optional[str] = typer.Option(
        None,
        "--formats",
        "-f",
        help="Comma-separated report formats (html,docx,xlsx)",
    ),
    title: Optional[str] = typer.Option(
        None, "--title", help="Report title"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Enable debug logging"
    ),
    nuclei_templates: Optional[str] = typer.Option(
        None, "--nuclei-templates", help="Path to external nuclei template directory"
    ),
    nuclei_default_templates: bool = typer.Option(
        True, "--nuclei-default-templates/--no-nuclei-default-templates",
        help="Include default nuclei templates (disable to run external only)"
    ),
    skip_screenshots: bool = typer.Option(
        False, "--skip-screenshots", help="Skip web endpoint screenshots"
    ),
    skip_enum4linux: bool = typer.Option(
        False, "--skip-enum4linux", help="Skip SMB/NetBIOS enumeration via enum4linux"
    ),
    skip_nikto: bool = typer.Option(
        False, "--skip-nikto", help="Skip Nikto web server scanning"
    ),
    skip_netexec: bool = typer.Option(
        False, "--skip-netexec", help="Skip NetExec network enumeration"
    ),
    config_file: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to wireghost.yml config"
    ),
) -> None:
    """Run a full security scan against TARGET."""
    from wireghost.config import ScanConfig
    from wireghost.pipeline.orchestrator import run_pipeline

    overrides: dict[str, object] = {
        "output_dir": output_dir,
        "parallelism": parallelism,
        "skip_nuclei": skip_nuclei,
        "skip_vuln": skip_vuln,
        "tool_timeout": timeout,
        "verbose": verbose,
        "nuclei_templates": nuclei_templates,
        "nuclei_default_templates": nuclei_default_templates,
        "skip_screenshots": skip_screenshots,
        "skip_enum4linux": skip_enum4linux,
        "skip_nikto": skip_nikto,
        "skip_netexec": skip_netexec,
    }
    if report_formats is not None:
        overrides["report_formats"] = [
            f.strip() for f in report_formats.split(",") if f.strip()
        ]
    if title is not None:
        overrides["report_title"] = title

    cfg = ScanConfig.load(
        target=target,
        config_path=config_file,
        **overrides,
    )

    cfg.output_dir = cfg.output_dir.resolve()
    console.print(f"[bold green]Wire_Ghost v{__version__}[/]")
    console.print(f"Target: [bold]{cfg.target}[/]")
    console.print(f"Output: {cfg.output_dir}")

    report = asyncio.run(run_pipeline(cfg))

    console.print()
    console.print("[bold green]Scan complete![/]")
    console.print(f"  Hosts:    {len(report.hosts)}")
    console.print(f"  Ports:    {report.total_open_ports}")
    console.print(f"  Findings: {len(report.findings)}")


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


# ── Mount domain apps ─────────────────────────────────────────────────

from wireghost.cli.auth import app as auth_app
app.add_typer(auth_app, name="auth", help="Authentication")

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
