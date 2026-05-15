"""wireghost deploy — remote SSH deployment command."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from wireghost.deploy.engine import DeployConfig, DeployResult, check_ssh, deploy

app = typer.Typer(name="deploy", help="Deploy Wire_Ghost to a remote host via SSH")
console = Console(stderr=True)


@app.callback(invoke_without_command=True)
def deploy_cmd(
    target: str = typer.Option(
        ..., "--target", help="Target host IP or hostname for deployment"
    ),
    user: str = typer.Option(
        "root", "--user", "-u", help="SSH user"
    ),
    ssh_key: Optional[Path] = typer.Option(
        None, "--ssh-key", "-i", help="Path to SSH private key"
    ),
    ssh_password: Optional[str] = typer.Option(
        None, "--password", "-p", help="SSH password (prompt if omitted and no key)"
    ),
    ssh_port: int = typer.Option(
        22, "--port", "-P", help="SSH port"
    ),
    mode: str = typer.Option(
        "docker", "--mode", "-m", help="Install mode: 'docker' or 'host'"
    ),
    with_msf: bool = typer.Option(
        False, "--with-msf", help="Include Metasploit Framework (~1.5GB extra)"
    ),
    web_host: Optional[str] = typer.Option(
        None, "--web-host", help="Portal hostname (defaults to target IP)"
    ),
    web_port: int = typer.Option(
        443, "--web-port", help="Portal HTTPS port"
    ),
    bundle: Optional[Path] = typer.Option(
        None, "--bundle", "-b", help="Use pre-built offline bundle (skip build)"
    ),
    skip_build: bool = typer.Option(
        False, "--no-build", help="Require --bundle; skip running offline-export.sh"
    ),
    skip_compress: bool = typer.Option(
        False, "--skip-compress", help="Skip bundle compression (faster build, larger transfer)"
    ),
    skip_health_check: bool = typer.Option(
        False, "--skip-health", help="Skip post-deploy health verification"
    ),
    check: bool = typer.Option(
        False, "--check", help="Only verify SSH connectivity, do not deploy"
    ),
) -> None:
    """Deploy Wire_Ghost to a remote host via SSH.

    Builds an offline bundle, transfers it via SCP, and runs the installer
    non-interactively on the target host.

    Examples:
        wireghost deploy 10.0.0.5                           # Deploy with default settings
        wireghost deploy 10.0.0.5 -u admin -i ~/.ssh/id_rsa # Key-based auth
        wireghost deploy 10.0.0.5 --mode host --with-msf    # Host mode + Metasploit
        wireghost deploy 10.0.0.5 --bundle ./offline.tar.gz # Use pre-built bundle
        wireghost deploy 10.0.0.5 --check                   # Only check SSH
    """
    cfg = DeployConfig(
        target_host=target,
        ssh_user=user,
        ssh_port=ssh_port,
        ssh_key=ssh_key,
        ssh_password=ssh_password,
        install_mode=mode,
        with_msf=with_msf,
        web_host=web_host,
        web_port=web_port,
        skip_compress=skip_compress,
        bundle_path=bundle,
        skip_health_check=skip_health_check,
    )

    if mode not in ("docker", "host"):
        console.print(f"[bold red]Invalid mode:[/] {mode} — use 'docker' or 'host'")
        raise typer.Exit(code=1)

    if skip_build and not bundle:
        console.print("[bold red]--no-build requires --bundle[/]")
        raise typer.Exit(code=1)

    if not ssh_key and not ssh_password:
        import getpass
        console.print(f"[dim]No SSH key or password provided. Prompting for password...[/]")
        cfg.ssh_password = getpass.getpass(f"SSH password for {user}@{target}: ")

    # ── Check mode ──────────────────────────────────────────────────
    if check:
        console.print(f"Checking SSH to [bold]{user}@{target}:{ssh_port}[/] ...")
        if check_ssh(cfg):
            console.print(f"[bold green]SSH connection to {target} verified[/]")
        else:
            console.print(f"[bold red]SSH connection to {target} failed[/]")
            raise typer.Exit(code=1)
        return

    # ── Deploy ──────────────────────────────────────────────────────
    console.print()
    console.print(Panel.fit(
        f"[bold]Target:[/] {user}@{target}:{ssh_port}\n"
        f"[bold]Mode:[/] {mode}\n"
        f"[bold]Metasploit:[/] {'yes' if with_msf else 'no'}\n"
        f"[bold]Bundle:[/] {bundle or 'auto-build'}",
        title="Wire_Ghost Remote Deploy",
        border_style="cyan",
    ))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Deploying...", total=None)
        result = deploy(cfg)
        progress.remove_task(task)

    # ── Result ──────────────────────────────────────────────────────
    _print_result(result, cfg)


def _print_result(result: DeployResult, cfg: DeployConfig) -> None:
    """Display deployment result."""
    console.print()

    if result.success:
        console.print(Panel.fit(
            f"[bold green]Deployment successful![/]\n\n"
            f"[bold]Host:[/]      {result.host}\n"
            f"[bold]Duration:[/]  {result.duration:.0f}s\n"
            f"[bold]Setup URL:[/] [cyan]{result.setup_url}[/]\n"
            f"[bold]Login URL:[/] [cyan]{result.login_url}[/]\n\n"
            f"[dim]Open the Setup URL in your browser to create the admin account.[/]\n"
            f"[dim]Accept the self-signed certificate warning if prompted.[/]",
            title="Deploy Complete",
            border_style="green",
        ))

        # Print last ~20 lines of remote output for context
        if result.output:
            console.print()
            console.print("[dim]Remote output (last lines):[/]")
            for line in result.output.splitlines()[-20:]:
                console.print(f"  [dim]{line}[/]")
    else:
        console.print(Panel.fit(
            f"[bold red]Deployment failed![/]\n\n"
            f"[bold]Errors:[/]\n" +
            "\n".join(f"  - {e}" for e in result.errors),
            title="Deploy Failed",
            border_style="red",
        ))
        if result.output:
            console.print()
            console.print("[dim]Remote output:[/]")
            for line in result.output.splitlines()[-40:]:
                console.print(f"  [dim]{line}[/]")

    console.print()
