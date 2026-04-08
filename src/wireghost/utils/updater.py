"""Updater — updates tools, feeds, and wireghost itself."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from rich.console import Console

console = Console(stderr=True)

# ProjectDiscovery tools — download latest binary from GitHub releases
_PD_TOOLS = {
    "nuclei": "projectdiscovery/nuclei",
    "httpx": "projectdiscovery/httpx",
    "naabu": "projectdiscovery/naabu",
}

_APT_TOOLS = ["nmap", "fping", "masscan", "searchsploit"]


def _run(cmd: list[str], label: str, timeout: int = 120) -> bool:
    """Run a command, print status, return True on success."""
    console.print(f"  [cyan]{label}[/]")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode == 0:
            # Print last meaningful line of output
            out = (result.stdout or result.stderr or "").strip().split("\n")
            last = out[-1] if out else ""
            if last:
                console.print(f"    [dim]{last[:100]}[/]")
            return True
        console.print(f"    [yellow]Exit code {result.returncode}[/]")
        if result.stderr:
            console.print(f"    [dim]{result.stderr.strip()[:150]}[/]")
        return False
    except FileNotFoundError:
        console.print(f"    [yellow]Not installed, skipping[/]")
        return False
    except subprocess.TimeoutExpired:
        console.print(f"    [yellow]Timed out[/]")
        return False


def update_tools() -> None:
    """Update all security tools to latest versions."""
    console.print("\n[bold]Updating tools...[/]")

    # APT tools
    has_apt = shutil.which("apt-get") is not None
    if has_apt:
        _run(["sudo", "apt-get", "update", "-qq"], "apt update", timeout=60)
        for tool in _APT_TOOLS:
            if shutil.which(tool):
                _run(
                    ["sudo", "apt-get", "install", "-y", "--only-upgrade", tool],
                    f"apt upgrade {tool}",
                )

    # ProjectDiscovery tools — re-download latest binaries
    import json
    import platform
    import tempfile
    import urllib.request
    import zipfile

    arch = "amd64" if platform.machine() in ("x86_64", "amd64") else "arm64"
    target = f"linux_{arch}.zip"

    for tool_name, repo in _PD_TOOLS.items():
        if not shutil.which(tool_name):
            console.print(f"  [dim]{tool_name}: not installed, skipping[/]")
            continue

        console.print(f"  [cyan]Updating {tool_name}...[/]")
        try:
            api = f"https://api.github.com/repos/{repo}/releases/latest"
            req = urllib.request.Request(api, headers={"User-Agent": "wireghost"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())

            asset_url = None
            for asset in data.get("assets", []):
                if target in asset.get("name", ""):
                    asset_url = asset["browser_download_url"]
                    break

            if not asset_url:
                console.print(f"    [yellow]No binary found for {target}[/]")
                continue

            with tempfile.TemporaryDirectory() as tmp:
                zip_path = Path(tmp) / f"{tool_name}.zip"
                urllib.request.urlretrieve(asset_url, str(zip_path))
                with zipfile.ZipFile(zip_path) as zf:
                    for name in zf.namelist():
                        if name == tool_name or name.endswith(f"/{tool_name}"):
                            zf.extract(name, tmp)
                            extracted = Path(tmp) / name
                            # Try /usr/local/bin first, fall back to ~/.local/bin
                            for dest_dir in [Path("/usr/local/bin"), Path.home() / ".local" / "bin"]:
                                dest = dest_dir / tool_name
                                try:
                                    subprocess.run(
                                        ["cp", str(extracted), str(dest)],
                                        check=True, capture_output=True,
                                    )
                                    subprocess.run(
                                        ["chmod", "+x", str(dest)],
                                        check=True, capture_output=True,
                                    )
                                    ver = data.get("tag_name", "latest")
                                    console.print(f"    [green]Updated to {ver}[/]")
                                    break
                                except subprocess.CalledProcessError:
                                    # Try with sudo for /usr/local/bin
                                    try:
                                        subprocess.run(
                                            ["sudo", "cp", str(extracted), str(dest)],
                                            check=True, capture_output=True,
                                        )
                                        subprocess.run(
                                            ["sudo", "chmod", "+x", str(dest)],
                                            check=True, capture_output=True,
                                        )
                                        ver = data.get("tag_name", "latest")
                                        console.print(f"    [green]Updated to {ver}[/]")
                                        break
                                    except subprocess.CalledProcessError:
                                        continue
                            break
        except Exception as e:
            console.print(f"    [red]Failed: {e}[/]")


def update_feeds() -> None:
    """Update vulnerability test feeds."""
    console.print("\n[bold]Updating feeds...[/]")

    # Nuclei templates
    if shutil.which("nuclei"):
        _run(["nuclei", "-update-templates"], "nuclei templates", timeout=120)

    # Searchsploit database
    if shutil.which("searchsploit"):
        _run(["searchsploit", "-u"], "searchsploit database", timeout=120)

    # OpenVAS NASL feeds (if scannerctl or greenbone-feed-sync available)
    if shutil.which("greenbone-feed-sync"):
        _run(
            ["greenbone-feed-sync", "--type", "nasl"],
            "OpenVAS NASL feeds (greenbone-feed-sync)",
            timeout=600,
        )
    elif shutil.which("scannerctl"):
        console.print("  [dim]scannerctl feed update requires feed path config[/]")


def update_self() -> None:
    """Update wireghost from GitHub."""
    console.print("\n[bold]Updating wireghost...[/]")

    # Find the repo root
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        console.print("  [yellow]Not a git repo, skipping self-update[/]")
        return

    repo_root = Path(result.stdout.strip())

    # Git pull
    ok = _run(["git", "-C", str(repo_root), "pull", "--ff-only"], "git pull")
    if not ok:
        console.print("  [yellow]git pull failed — try manually[/]")
        return

    # Reinstall
    _run(
        ["pip", "install", "-e", str(repo_root)],
        "pip install (upgrade)",
        timeout=120,
    )

    # Show new version
    try:
        from wireghost import __version__
        console.print(f"  [green]wireghost {__version__}[/]")
    except Exception:
        pass


def update_all() -> None:
    """Update everything: tools, feeds, and wireghost."""
    update_tools()
    update_feeds()
    update_self()
    console.print("\n[bold green]All updates complete![/]")
