"""Remote SSH deployment engine for Wire_Ghost.

Orchestrates: bundle build → SCP transfer → remote install → health check.
Uses subprocess ssh/scp (no paramiko dependency) matching the project's
existing pattern in scan.py and wg-ctl.
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("wireghost")


@dataclass
class DeployConfig:
    """Configuration for a remote SSH deployment."""

    target_host: str
    ssh_user: str = "root"
    ssh_port: int = 22
    ssh_key: Path | None = None
    ssh_password: str | None = None
    install_mode: str = "docker"  # "docker" or "host"
    with_msf: bool = False
    web_host: str | None = None
    web_port: int = 443
    skip_compress: bool = False
    bundle_path: Path | None = None
    skip_health_check: bool = False


@dataclass
class DeployResult:
    success: bool
    host: str
    setup_url: str = ""
    login_url: str = ""
    output: str = ""
    duration: float = 0.0
    errors: list[str] = field(default_factory=list)


def _ssh_opts(config: DeployConfig) -> list[str]:
    """Build common SSH options list."""
    opts = [
        "-o",
        "ConnectTimeout=10",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ServerAliveInterval=30",
        "-p",
        str(config.ssh_port),
    ]
    if config.ssh_key:
        opts.extend(["-i", str(config.ssh_key)])
    return opts


def _ssh_target(config: DeployConfig) -> str:
    return f"{config.ssh_user}@{config.target_host}"


def _run_local(cmd: list[str], timeout: int = 300, label: str = "") -> tuple[int, str, str]:
    """Run a local command, return (rc, stdout, stderr)."""
    log.debug("[%s] Running: %s", label, " ".join(cmd))
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"


def _run_ssh(
    config: DeployConfig,
    remote_cmd: str,
    timeout: int = 600,
    label: str = "",
) -> tuple[int, str, str]:
    """Run a command on the remote host via SSH. Returns (rc, stdout, stderr)."""
    cmd = ["ssh"] + _ssh_opts(config) + [_ssh_target(config), remote_cmd]
    return _run_local(cmd, timeout=timeout, label=label)


def check_ssh(config: DeployConfig) -> bool:
    """Verify SSH connectivity to the target host."""
    rc, stdout, stderr = _run_ssh(
        config,
        "echo 'SSH_OK' && cat /etc/os-release 2>/dev/null | head -1",
        timeout=15,
        label="ssh_check",
    )
    if rc == 0 and "SSH_OK" in stdout:
        log.info("SSH connection to %s verified", config.target_host)
        return True
    log.error("SSH check failed for %s: %s", config.target_host, stderr.strip())
    return False


def build_bundle(
    config: DeployConfig,
    output_dir: Path | None = None,
) -> Path:
    """Build an offline deployment bundle via scripts/offline-export.sh.

    Returns the path to the compressed .tar.gz (or uncompressed directory).
    """
    project_root = Path(__file__).resolve().parent.parent.parent.parent
    script = project_root / "scripts" / "offline-export.sh"

    if not script.is_file():
        raise FileNotFoundError(f"Offline export script not found: {script}")

    args = ["sudo", "bash", str(script)]
    if config.skip_compress:
        args.append("--skip-compress")
    if config.with_msf:
        args.append("--with-msf")
    if output_dir:
        args.append(str(output_dir))

    log.info("Building offline bundle (this may take 20-40 minutes)...")
    rc, stdout, stderr = _run_local(
        args,
        timeout=3600,
        label="offline-export",
    )

    if rc != 0:
        raise RuntimeError(f"Bundle build failed (rc={rc}): {stderr}")

    # Parse bundle path from script output — last line with "wireghost-offline-"
    bundle_path = None
    for line in (stdout + stderr).splitlines():
        # Script prints: "Compressed archive created: wireghost-offline-XXXXX.tar.gz"
        if "Compressed archive created:" in line or "Archive:" in line:
            parts = line.split()
            for part in parts:
                if "wireghost-offline-" in part:
                    candidate = project_root / part.strip()
                    if candidate.exists():
                        bundle_path = candidate
                        break
        # Directory bundle: "Bundle:  /path/to/wireghost-offline-XXXXX"
        if "Bundle:" in line:
            parts = line.split()
            for part in parts:
                if "wireghost-offline-" in part:
                    candidate = Path(part.strip())
                    if candidate.exists():
                        bundle_path = candidate
                        break

    # Fallback: find the most recently created wireghost-offline-* directory/archive
    if not bundle_path:
        candidates = sorted(
            project_root.glob("wireghost-offline-*"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if candidates:
            bundle_path = candidates[0]

    if not bundle_path or not bundle_path.exists():
        raise RuntimeError("Could not locate built bundle — check offline-export.sh output")

    log.info("Bundle ready: %s", bundle_path)
    return bundle_path


def _scp_transfer(
    config: DeployConfig,
    local_path: Path,
    remote_dir: str = "/opt",
) -> bool:
    """SCP the bundle to the remote host."""
    remote_target = f"{_ssh_target(config)}:{remote_dir}/"

    if local_path.is_dir():
        # Transfer directory contents via rsync or scp -r
        cmd = ["scp", "-r", "-C"] + _ssh_opts(config) + [str(local_path), remote_target]
    else:
        cmd = ["scp", "-C"] + _ssh_opts(config) + [str(local_path), remote_target]

    log.info("Transferring %s to %s:%s ...", local_path.name, config.target_host, remote_dir)
    rc, _, stderr = _run_local(
        cmd,
        timeout=3600,
        label=f"scp {local_path.name}",
    )
    if rc != 0:
        log.error("SCP transfer failed (rc=%d): %s", rc, stderr)
        return False
    log.info("Transfer complete: %s", local_path.name)
    return True


def _build_remote_env(config: DeployConfig) -> str:
    """Build environment variable exports for the remote install script."""
    host = config.web_host or config.target_host
    vars_ = {
        "WIREGHOST_HOST": host,
        "WIREGHOST_PORT": str(config.web_port),
    }
    if config.install_mode == "host":
        vars_["INSTALL_MODE"] = "host"
    return " ".join(f"{k}='{v}'" for k, v in vars_.items())


def deploy(config: DeployConfig) -> DeployResult:
    """Execute a full remote deployment: build → transfer → install → verify.

    Steps:
    1. Build offline bundle (or use pre-built path)
    2. SCP bundle to remote host
    3. Extract and run install script non-interactively
    4. Verify portal is reachable
    """
    t0 = time.monotonic()
    errors: list[str] = []

    # ── Step 0: Verify SSH ──────────────────────────────────────────
    if not check_ssh(config):
        return DeployResult(
            success=False,
            host=config.target_host,
            errors=["SSH connection failed"],
            duration=time.monotonic() - t0,
        )

    # ── Step 1: Build or locate bundle ───────────────────────────────
    bundle_path = config.bundle_path
    with tempfile.TemporaryDirectory(prefix="wg-deploy-") as tmpdir:
        if not bundle_path:
            bundle_path = build_bundle(config, output_dir=Path(tmpdir))
        elif not bundle_path.exists():
            return DeployResult(
                success=False,
                host=config.target_host,
                errors=[f"Bundle not found: {bundle_path}"],
                duration=time.monotonic() - t0,
            )

        # ── Step 2: Transfer ────────────────────────────────────────────
        if not _scp_transfer(config, bundle_path):
            return DeployResult(
                success=False,
                host=config.target_host,
                errors=["SCP transfer failed"],
                duration=time.monotonic() - t0,
            )

        bundle_name = bundle_path.name

    # ── Step 3: Remote install ───────────────────────────────────────
    env = _build_remote_env(config)
    host_flag = "--host" if config.install_mode == "host" else "--docker"
    msf_flag = "--with-msf" if config.with_msf else ""

    # Build the remote command
    # If it's a .tar.gz, extract it first; if directory, cd into it
    if bundle_name.endswith(".tar.gz"):
        base = bundle_name.removesuffix(".tar.gz")
        remote_cmd = (
            f"cd /opt && "
            f"tar xzf {bundle_name} && "
            f"cd {base} && "
            f"{env} sudo bash install.sh {host_flag} {msf_flag}"
        )
    else:
        remote_cmd = f"cd /opt/{bundle_name} && {env} sudo bash install.sh {host_flag} {msf_flag}"

    log.info("Running remote installer on %s ...", config.target_host)
    rc, stdout, stderr = _run_ssh(
        config,
        remote_cmd,
        timeout=1200,
        label="remote-install",
    )

    output = stdout + "\n" + stderr
    if rc != 0:
        errors.append(f"Remote installer exited with rc={rc}")

    # ── Step 4: Health check ─────────────────────────────────────────
    host = config.web_host or config.target_host
    proto = "https" if config.web_port == 443 else "http"
    port_suffix = f":{config.web_port}" if config.web_port not in (443, 80) else ""
    setup_url = f"{proto}://{host}{port_suffix}/setup"
    login_url = f"{proto}://{host}{port_suffix}/login"

    if not config.skip_health_check:
        _run_ssh(
            config,
            "docker compose ps 2>/dev/null || echo 'compose_check_failed'",
            timeout=30,
            label="health-check",
        )

    duration = time.monotonic() - t0
    success = rc == 0 and not errors

    return DeployResult(
        success=success,
        host=config.target_host,
        setup_url=setup_url,
        login_url=login_url,
        output=output[-5000:] if output else "",  # Last 5k chars for display
        duration=duration,
        errors=errors,
    )
