"""Auto-installer for missing external tools."""

from __future__ import annotations

import logging
import os
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path

from rich.console import Console

log = logging.getLogger("wireghost")
console = Console(stderr=True)

# Tools installable via apt
_APT_TOOLS = {
    "nmap": "nmap",
    "fping": "fping",
    "masscan": "masscan",
    "searchsploit": "exploitdb",
    "nikto": "nikto",
}

# ProjectDiscovery tools — downloaded as pre-built binaries
_PD_TOOLS = {
    "nuclei": "projectdiscovery/nuclei",
    "httpx": "projectdiscovery/httpx",
    "naabu": "projectdiscovery/naabu",
}

# Tools installable via pip
_PIP_TOOLS = {
    "nxc": "netexec",
}

_INSTALL_DIR = Path("/usr/local/bin")


def _get_arch() -> str:
    """Map platform.machine() to GitHub release naming."""
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    return machine


def _install_apt(package: str) -> bool:
    """Install a package via apt. Returns True on success."""
    console.print(f"  [cyan]Installing {package} via apt...[/]")
    try:
        result = subprocess.run(
            ["sudo", "apt-get", "install", "-y", package],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            console.print(f"  [green]Installed {package}[/]")
            return True
        console.print(f"  [red]apt install failed:[/] {result.stderr.strip()}")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        console.print(f"  [red]apt install failed:[/] {e}")
    return False


def _install_pd_binary(tool_name: str, repo: str) -> bool:
    """Download and install a ProjectDiscovery tool binary from GitHub releases."""
    arch = _get_arch()
    console.print(f"  [cyan]Downloading {tool_name} from GitHub...[/]")

    try:
        # Get latest release download URL
        import json
        import urllib.request

        api_url = f"https://api.github.com/repos/{repo}/releases/latest"
        req = urllib.request.Request(api_url, headers={"User-Agent": "wireghost"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())

        # Find the linux_amd64.zip asset
        target = f"linux_{arch}.zip"
        asset_url = None
        for asset in data.get("assets", []):
            if target in asset.get("name", ""):
                asset_url = asset["browser_download_url"]
                break

        if not asset_url:
            console.print(f"  [red]No {target} binary found in latest release[/]")
            return False

        # Download and extract
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = Path(tmp) / f"{tool_name}.zip"
            console.print(f"  [dim]{asset_url}[/]")

            urllib.request.urlretrieve(asset_url, str(zip_path))

            import zipfile
            with zipfile.ZipFile(zip_path) as zf:
                # Find the binary in the zip
                for name in zf.namelist():
                    if name == tool_name or name.endswith(f"/{tool_name}"):
                        zf.extract(name, tmp)
                        extracted = Path(tmp) / name
                        dest = _INSTALL_DIR / tool_name
                        # Need sudo to write to /usr/local/bin
                        subprocess.run(
                            ["sudo", "cp", str(extracted), str(dest)],
                            check=True,
                        )
                        subprocess.run(
                            ["sudo", "chmod", "+x", str(dest)],
                            check=True,
                        )
                        console.print(f"  [green]Installed {tool_name} to {dest}[/]")
                        return True

            console.print(f"  [red]Binary '{tool_name}' not found in zip[/]")

    except Exception as e:
        console.print(f"  [red]Download failed:[/] {e}")
    return False


def _install_pip(package: str) -> bool:
    """Install a package via pip. Returns True on success."""
    console.print(f"  [cyan]Installing {package} via pip...[/]")
    try:
        result = subprocess.run(
            ["pip", "install", "--quiet", package],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            console.print(f"  [green]Installed {package}[/]")
            return True
        console.print(f"  [red]pip install failed:[/] {result.stderr.strip()}")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        console.print(f"  [red]pip install failed:[/] {e}")
    return False


def install_missing_tools(tools: list[str]) -> list[str]:
    """Check which tools are missing and attempt to install them.

    Returns list of tools that are still missing after install attempts.
    """
    missing = [t for t in tools if shutil.which(t) is None]
    if not missing:
        return []

    console.print(
        f"\n[bold yellow]Missing tools:[/] {', '.join(missing)}"
    )
    console.print("[bold]Attempting auto-install...[/]\n")

    still_missing: list[str] = []

    for tool in missing:
        if tool in _APT_TOOLS:
            if not _install_apt(_APT_TOOLS[tool]):
                still_missing.append(tool)
        elif tool in _PD_TOOLS:
            if not _install_pd_binary(tool, _PD_TOOLS[tool]):
                still_missing.append(tool)
        elif tool in _PIP_TOOLS:
            if not _install_pip(_PIP_TOOLS[tool]):
                still_missing.append(tool)
        else:
            console.print(f"  [yellow]Don't know how to install: {tool}[/]")
            still_missing.append(tool)

    # Verify installs actually worked (hash cache may be stale)
    final_missing = [t for t in tools if shutil.which(t) is None]
    if final_missing:
        console.print(
            f"\n[bold red]Still missing after install:[/] {', '.join(final_missing)}"
        )
    else:
        console.print("\n[bold green]All tools installed successfully![/]")

    return final_missing
