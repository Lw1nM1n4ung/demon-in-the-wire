"""wireghost scan — local pipeline runner with tmux integration."""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from wireghost import __version__

app = typer.Typer(name="scan", help="Run a local security scan")
console = Console(stderr=True)


def _slugify_target(target: str) -> str:
    """Slugify target for tmux session name: 192.168.1.0/24 → wg-192.168.1.0-24."""
    import re
    slug = re.sub(r"[^a-zA-Z0-9./-]", "", target)
    slug = slug.replace("/", "-")
    return f"wg-{slug}"


def _has_tmux() -> bool:
    return shutil.which("tmux") is not None


@app.callback(invoke_without_command=True)
def scan(
    target: str = typer.Option(..., "--target", help="Target IP, CIDR range, or hostname"),
    output_dir: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output directory (default: ./output)"
    ),
    parallelism: int = typer.Option(
        10, "--parallelism", "-j", help="Max concurrent host scans"
    ),
    skip_nuclei: bool = typer.Option(False, "--skip-nuclei"),
    skip_vuln: bool = typer.Option(False, "--skip-vuln"),
    skip_screenshots: bool = typer.Option(False, "--skip-screenshots"),
    skip_enum4linux: bool = typer.Option(False, "--skip-enum4linux"),
    skip_nikto: bool = typer.Option(False, "--skip-nikto"),
    skip_netexec: bool = typer.Option(False, "--skip-netexec"),
    skip_msf: bool = typer.Option(False, "--skip-msf"),
    skip_getsploit: bool = typer.Option(False, "--skip-getsploit"),
    skip_brute_force: bool = typer.Option(
        False, "--skip-brute-force",
        help="Exclude brute-force scripts (nmap vnc-brute, dns-brute, etc.)",
    ),
    skip_fingerprintx: bool = typer.Option(
        False, "--skip-fingerprintx",
        help="Skip fingerprintx service identification during port scan",
    ),
    timeout: float = typer.Option(3600.0, "--timeout", "-t", help="Per-tool timeout"),
    report_formats: Optional[str] = typer.Option(
        None, "--formats", "-f", help="Comma-separated report formats"
    ),
    title: Optional[str] = typer.Option(None, "--title", help="Report title"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    nuclei_templates: Optional[str] = typer.Option(
        None, "--nuclei-templates", help="External nuclei template directory"
    ),
    nuclei_default_templates: bool = typer.Option(
        True, "--nuclei-default-templates/--no-nuclei-default-templates"
    ),
    config_file: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to wireghost.yml config"
    ),
    no_tmux: bool = typer.Option(False, "--no-tmux", help="Run in foreground (no tmux)"),
    attach: bool = typer.Option(
        False, "--attach", help="Attach to a running scan"
    ),
    list_sessions: bool = typer.Option(
        False, "--list", help="List running wg-* tmux sessions"
    ),
    kill_target: Optional[str] = typer.Option(
        None, "--kill", help="Kill a running scan by target"
    ),
) -> None:
    """Run a full security scan pipeline against a target.

    Default: launches in a detached tmux session named after the target.
    Use --no-tmux to run in the foreground without tmux.
    """
    # ── management commands ──────────────────────────────────────
    if list_sessions:
        _list_sessions()
        return

    if kill_target:
        _kill_session(kill_target)
        return

    if attach:
        _attach(target)
        return

    # ── import pipeline ──────────────────────────────────────────
    from wireghost.config import ScanConfig

    overrides: dict = {
        "output_dir": output_dir,
        "parallelism": parallelism,
        "skip_nuclei": skip_nuclei,
        "skip_vuln": skip_vuln,
        "skip_screenshots": skip_screenshots,
        "skip_enum4linux": skip_enum4linux,
        "skip_nikto": skip_nikto,
        "skip_netexec": skip_netexec,
        "skip_msf_scan": skip_msf,
        "skip_getsploit": skip_getsploit,
        "skip_brute_force": skip_brute_force,
        "skip_fingerprintx": skip_fingerprintx,
        "tool_timeout": timeout,
        "verbose": verbose,
        "nuclei_templates": nuclei_templates,
        "nuclei_default_templates": nuclei_default_templates,
    }
    if report_formats:
        overrides["report_formats"] = [
            f.strip() for f in report_formats.split(",") if f.strip()
        ]
    if title:
        overrides["report_title"] = title

    cfg = ScanConfig.load(target=target, config_path=config_file, **overrides)
    cfg.output_dir = cfg.output_dir.resolve()

    # ── tmux path ────────────────────────────────────────────────
    session_name = _slugify_target(target)

    if not no_tmux and _has_tmux():
        _launch_tmux(session_name, target, cfg)
    else:
        if not no_tmux:
            console.print("[bold yellow]tmux not found — running in foreground[/]")
        _run_foreground(cfg)


def _launch_tmux(session_name: str, target: str, cfg) -> None:
    """Launch a detached tmux session with scan pipeline."""
    python = sys.executable
    cmd_parts = [
        python, "-m", "wireghost", "scan", "--target", target,
        "--no-tmux",
        "-o", str(cfg.output_dir),
        "-j", str(cfg.parallelism),
    ]
    if cfg.skip_nuclei:
        cmd_parts.append("--skip-nuclei")
    if cfg.skip_vuln:
        cmd_parts.append("--skip-vuln")
    if cfg.skip_screenshots:
        cmd_parts.append("--skip-screenshots")
    if cfg.skip_enum4linux:
        cmd_parts.append("--skip-enum4linux")
    if cfg.skip_nikto:
        cmd_parts.append("--skip-nikto")
    if cfg.skip_netexec:
        cmd_parts.append("--skip-netexec")
    if cfg.skip_msf_scan:
        cmd_parts.append("--skip-msf")
    if cfg.skip_getsploit:
        cmd_parts.append("--skip-getsploit")
    if cfg.skip_brute_force:
        cmd_parts.append("--skip-brute-force")
    if cfg.skip_fingerprintx:
        cmd_parts.append("--skip-fingerprintx")
    if cfg.tool_timeout != 3600.0:
        cmd_parts.extend(["-t", str(cfg.tool_timeout)])
    if cfg.nuclei_templates:
        cmd_parts.extend(["--nuclei-templates", cfg.nuclei_templates])
    if not cfg.nuclei_default_templates:
        cmd_parts.append("--no-nuclei-default-templates")
    if cfg.report_formats:
        cmd_parts.extend(["-f", ",".join(cfg.report_formats)])
    if cfg.report_title != "Security Assessment Summary Report":
        cmd_parts.extend(["--title", cfg.report_title])
    if cfg.verbose:
        cmd_parts.append("--verbose")

    scan_cmd = " ".join(f"'{p}'" if " " in str(p) else str(p) for p in cmd_parts)

    # Kill existing session if present
    try:
        subprocess.run(
            ["tmux", "kill-session", "-t", session_name],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass

    # Create new detached session
    subprocess.run(
        ["tmux", "new-session", "-d", "-s", session_name, "-n", "scan"],
        check=True, timeout=10,
    )

    # Top pane (80%): scan output
    subprocess.run(
        ["tmux", "send-keys", "-t", f"{session_name}:scan.0",
         scan_cmd, "Enter"],
        check=True, timeout=5,
    )

    # Create bottom pane (20%): status bar
    subprocess.run(
        ["tmux", "split-window", "-d", "-t", f"{session_name}:scan.0",
         "-l", "8"],
        check=True, timeout=5,
    )
    status_cmd = (
        f"while true; do "
        f" echo 'Target: {target} | Elapsed: $(date +%H:%M:%S) | "
        f"Press Ctrl-B d to detach'; "
        f" sleep 5; "
        f"done"
    )
    subprocess.run(
        ["tmux", "send-keys", "-t", f"{session_name}:scan.1",
         f"echo 'Wire_Ghost scan: {target}'; {status_cmd}", "Enter"],
        check=True, timeout=5,
    )

    # Select top pane
    subprocess.run(
        ["tmux", "select-pane", "-t", f"{session_name}:scan.0"],
        check=True, timeout=5,
    )

    console.print(f"[bold green]Created tmux session: {session_name}[/]")
    console.print(f"  Reattach: [bold]wireghost scan --attach {target}[/]")
    console.print(f"  Watch:    [bold]tmux attach -t {session_name}[/]")


def _run_foreground(cfg) -> None:
    """Run the scan pipeline in the foreground."""
    from wireghost.pipeline.orchestrator import run_pipeline

    console.print(f"[bold green]Wire_Ghost v{__version__}[/]")
    console.print(f"Target: [bold]{cfg.target}[/]")
    console.print(f"Output: {cfg.output_dir}")

    report = asyncio.run(run_pipeline(cfg))

    console.print()
    console.print("[bold green]Scan complete![/]")
    console.print(f"  Hosts:    {len(report.hosts)}")
    console.print(f"  Ports:    {report.total_open_ports}")
    console.print(f"  Findings: {len(report.findings)}")


def _attach(target: str) -> None:
    """Attach to a running scan tmux session."""
    session_name = _slugify_target(target)
    if not _has_tmux():
        console.print("[bold red]tmux not installed[/]")
        raise typer.Exit(code=1)

    # Check if session exists
    result = subprocess.run(
        ["tmux", "has-session", "-t", session_name],
        capture_output=True, timeout=5,
    )
    if result.returncode != 0:
        console.print(f"[bold red]Session not found:[/] {session_name}")
        console.print("Running sessions:")
        _list_sessions()
        raise typer.Exit(code=1)

    os.execvp("tmux", ["tmux", "attach-session", "-t", session_name])


def _kill_session(target: str) -> None:
    """Kill a running scan tmux session."""
    session_name = _slugify_target(target)
    try:
        subprocess.run(
            ["tmux", "kill-session", "-t", session_name],
            check=True, timeout=5,
        )
        console.print(f"[bold green]Killed session:[/] {session_name}")
    except subprocess.CalledProcessError:
        console.print(f"[bold yellow]Session not running:[/] {session_name}")
        raise typer.Exit(code=1)


def _list_sessions() -> None:
    """List all wg-* tmux sessions."""
    if not _has_tmux():
        console.print("[bold yellow]tmux not installed[/]")
        return

    result = subprocess.run(
        ["tmux", "list-sessions", "-F", "#{session_name} #{session_created}"],
        capture_output=True, text=True, timeout=5,
    )
    sessions = [
        line.split(" ", 1)
        for line in result.stdout.strip().split("\n")
        if line.startswith("wg-")
    ]
    if not sessions:
        console.print("[dim]No active wg-* scan sessions[/]")
        return

    from wireghost.cli.output import echo_table
    echo_table(
        "Active Scan Sessions",
        [("name", "Session"), ("created", "Started")],
        [{"name": s[0], "created": s[1] if len(s) > 1 else "—"} for s in sessions],
    )
