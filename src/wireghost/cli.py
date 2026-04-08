"""Wire_Ghost CLI -- scan, report, and config commands."""

from __future__ import annotations

import asyncio
import shutil
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from wireghost import __version__

app = typer.Typer(name="wireghost", help="Wire_Ghost security scanning toolkit")
console = Console(stderr=True)


@app.callback(invoke_without_command=True)
def main(
    version: bool = typer.Option(
        False, "--version", "-V", help="Show version and exit"
    ),
) -> None:
    """Wire_Ghost -- automated security scanning toolkit."""
    if version:
        typer.echo(f"wireghost {__version__}")
        raise typer.Exit()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target IP, CIDR range, or hostname"),
    output_dir: Path = typer.Option(
        Path("./output"), "--output", "-o", help="Output directory"
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
    skip_openvas: bool = typer.Option(
        True, "--skip-openvas/--no-skip-openvas", help="Skip/enable OpenVAS scanning"
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
        "skip_openvas": skip_openvas,
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
    console.print(f"[bold green]Scan complete![/]")
    console.print(f"  Hosts:    {len(report.hosts)}")
    console.print(f"  Ports:    {report.total_open_ports}")
    console.print(f"  Findings: {len(report.findings)}")


@app.command()
def report(
    scan_dir: Path = typer.Argument(
        ..., help="Path to existing scan output directory"
    ),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output directory for reports (default: <scan_dir>/reports)",
    ),
    formats: str = typer.Option(
        "html,docx,xlsx",
        "--formats",
        "-f",
        help="Comma-separated report formats",
    ),
    title: str = typer.Option(
        "Security Assessment Summary Report",
        "--title",
        help="Report title",
    ),
) -> None:
    """Re-generate reports from existing scan data."""
    from wireghost.config import ScanConfig
    from wireghost.models.report import ScanReport
    from wireghost.models.scan import Host
    from wireghost.parsers.nmap import parse_nmap_xml, parse_nmap_vuln_xml
    from wireghost.parsers.nuclei import parse_nuclei_json

    if not scan_dir.is_dir():
        console.print(f"[bold red]Error:[/] {scan_dir} is not a directory")
        raise typer.Exit(code=1)

    fmt_list = [f.strip() for f in formats.split(",") if f.strip()]
    reports_dir = output_dir or scan_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    # Re-parse hosts and findings from scan artifacts
    hosts: list[Host] = []
    findings = []

    ips_dir = scan_dir / "ips"
    if ips_dir.is_dir():
        for ip_dir in sorted(ips_dir.iterdir()):
            if not ip_dir.is_dir():
                continue

            # Port scan
            nmap_xml = ip_dir / "nmap_xml" / "portscan.xml"
            parsed_hosts = parse_nmap_xml(nmap_xml)
            host = parsed_hosts[0] if parsed_hosts else Host(ip=ip_dir.name)
            hosts.append(host)

            # Web endpoints
            endpoints_file = ip_dir / "web" / "endpoints.txt"
            if endpoints_file.is_file():
                host.web_endpoints = [
                    line.strip()
                    for line in endpoints_file.read_text().splitlines()
                    if line.strip()
                ]

            # Vuln findings
            vuln_dir = ip_dir / "vuln"
            if vuln_dir.is_dir():
                nuclei_json = vuln_dir / "nuclei.json"
                findings.extend(parse_nuclei_json(nuclei_json))

                nmap_vuln_xml = vuln_dir / "nmap_vuln.xml"
                findings.extend(parse_nmap_vuln_xml(nmap_vuln_xml))

    # Infer target from directory name
    target_name = scan_dir.name

    scan_report = ScanReport(
        target=target_name,
        hosts=hosts,
        findings=findings,
    )

    cfg = ScanConfig(
        target=target_name,
        output_dir=scan_dir.parent,
        report_formats=fmt_list,
        report_title=title,
    )

    try:
        from wireghost.reports import ReportEngine  # type: ignore[attr-defined]

        engine = ReportEngine(cfg, reports_dir)
        engine.generate(scan_report)
        console.print("[bold green]Reports generated![/]")
    except (ImportError, AttributeError):
        console.print(
            "[bold yellow]Warning:[/] Report engine not available. "
            "Install report renderers to enable this feature."
        )
        raise typer.Exit(code=1)


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
    """Copy wireghost.example.yml to wireghost.yml in the current directory."""
    dest = Path("wireghost.yml")
    if dest.exists():
        console.print(
            "[bold yellow]wireghost.yml already exists.[/] "
            "Remove it first to re-initialize."
        )
        raise typer.Exit(code=1)

    # Look for the example file relative to the package
    example = Path(__file__).resolve().parent.parent.parent / "wireghost.example.yml"
    if not example.is_file():
        # Fallback: look in cwd or project root
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
        # Generate a minimal config inline
        dest.write_text(
            "# Wire_Ghost configuration\n"
            "# target: \"192.168.1.0/24\"\n"
            "output_dir: \"./output\"\n"
            "parallelism: 10\n"
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
    """Print the resolved configuration."""
    from wireghost.config import ScanConfig

    cfg = ScanConfig.load()

    table = Table(title="Wire_Ghost Configuration", show_header=True)
    table.add_column("Setting", style="bold")
    table.add_column("Value")

    table.add_row("target", cfg.target or "(not set)")
    table.add_row("output_dir", str(cfg.output_dir))
    table.add_row("parallelism", str(cfg.parallelism))
    table.add_row("skip_nuclei", str(cfg.skip_nuclei))
    table.add_row("skip_vuln", str(cfg.skip_vuln))
    table.add_row("tool_timeout", str(cfg.tool_timeout))
    table.add_row("report_formats", ", ".join(cfg.report_formats))
    table.add_row("report_title", cfg.report_title)
    table.add_row("verbose", str(cfg.verbose))

    console.print(table)
