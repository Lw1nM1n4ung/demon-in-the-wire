"""Subprocess utilities for running external tools."""

from __future__ import annotations

import asyncio
import os
import shutil
from dataclasses import dataclass

from rich.console import Console

console = Console(stderr=True)


class ToolMissing(RuntimeError):
    """Raised when a required external tool is not found on PATH."""


async def check_tools(tools: list[str]) -> None:
    """Verify every tool in *tools* exists on PATH.

    Attempts auto-install for missing tools before raising.
    Raises :class:`ToolMissing` if tools are still missing after install.
    """
    missing = [t for t in tools if shutil.which(t) is None]
    if not missing:
        return

    auto_install = os.getenv("WIREGHOST_AUTO_INSTALL_TOOLS", "1").strip().lower()
    if auto_install in {"0", "false", "no", "off"}:
        still_missing = missing
    else:
        from wireghost.utils.installer import install_missing_tools
        still_missing = install_missing_tools(missing)

    if still_missing:
        raise ToolMissing(
            f"Required tool(s) not found: {', '.join(still_missing)}"
        )


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str


async def run_tool(
    cmd: list[str],
    timeout: int = 3600,
    label: str = "",
    cwd: str | None = None,
) -> RunResult:
    """Run an external command asynchronously and return its output.

    Parameters
    ----------
    cmd:
        Command and arguments, e.g. ``["nmap", "-sV", "10.0.0.1"]``.
    timeout:
        Maximum seconds to wait (default 3600).
    label:
        Human-readable label for console output.
    cwd:
        Working directory for the subprocess.
    """
    display = label or cmd[0]
    console.log(f"[bold cyan]Running:[/] {display}")

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
    )

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        console.log(f"[bold red]Timeout:[/] {display} after {timeout}s")
        return RunResult(returncode=-1, stdout="", stderr=f"Timeout after {timeout}s")

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")

    assert proc.returncode is not None
    if proc.returncode == 0:
        console.log(f"[bold green]Done:[/] {display}")
    else:
        console.log(
            f"[bold red]Failed:[/] {display} (rc={proc.returncode})"
        )

    return RunResult(returncode=proc.returncode, stdout=stdout, stderr=stderr)
