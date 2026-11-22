"""Network overload detector for host discovery.

Pings a set of targets (8.8.8.8 + auto-detected default gateway by default)
and pauses discovery when *all* targets go silent.  Discovery resumes
automatically once all targets answer again.

Pausing keeps the scan status ``running`` — the Celery task is not cancelled —
so no progress is lost and the live-discovery page shows a "Paused" banner.
"""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
from typing import Callable

from wireghost.utils.process import run_tool

log = logging.getLogger("wireghost")


class _TaskCancelled(Exception):
    """Raised when the Celery task is cancelled by user request."""


# Parses "default via 10.20.0.1 dev eth0" style lines from `ip route`.
_DEFAULT_ROUTE_RE = re.compile(r"default via ([\d.]+)")


async def _detect_gateway() -> str | None:
    """Return the default gateway IP, or None if it cannot be determined."""
    if shutil.which("ip") is None:
        return _detect_gateway_proc()
    try:
        proc = await asyncio.create_subprocess_exec(
            "ip",
            "route",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode(errors="replace")
    except Exception:  # pragma: no cover — best-effort only
        return _detect_gateway_proc()
    m = _DEFAULT_ROUTE_RE.search(output)
    return m.group(1) if m else _detect_gateway_proc()


def _detect_gateway_proc() -> str | None:
    """Fallback gateway lookup by parsing /proc/net/route.

    The worker image does not always ship iproute2, but /proc/net/route is
    always present on Linux.  The default route has destination 00000000 and
    the gateway is stored as a little-endian hex IPv4 address.
    """
    try:
        with open("/proc/net/route", encoding="utf-8") as f:
            next(f, None)  # skip header
            for line in f:
                fields = line.split()
                if len(fields) < 3 or fields[1] != "00000000":
                    continue
                raw = fields[2]
                if len(raw) != 8:
                    continue
                # /proc/net/route stores the gateway little-endian.
                octets = [int(raw[i : i + 2], 16) for i in (6, 4, 2, 0)]
                gateway = ".".join(str(o) for o in octets)
                if gateway != "0.0.0.0":
                    return gateway
    except Exception:  # pragma: no cover — best-effort only
        return None
    return None


class NetworkOverwatch:
    """Pause discovery when all monitored targets stop answering ping.

    Parameters
    ----------
    targets:
        List of IP addresses to ping.  Empty means "no overwatch".
    interval:
        Seconds between ping checks while paused.
    fail_threshold:
        Consecutive all-target failures before pausing.
    recover_threshold:
        Consecutive all-target successes before resuming.
    timeout:
        Per-ping timeout in seconds.
    """

    def __init__(
        self,
        targets: list[str],
        interval: float = 15.0,
        fail_threshold: int = 3,
        recover_threshold: int = 2,
        timeout: float = 5.0,
    ) -> None:
        self.targets = list(targets)
        self.interval = interval
        self.fail_threshold = fail_threshold
        self.recover_threshold = recover_threshold
        self.timeout = timeout
        self._consecutive_failures = 0
        self._consecutive_successes = 0
        self._paused = False

    @property
    def available(self) -> bool:
        """True when a usable ICMP probe binary is present.

        Without one every probe fails, which would look exactly like a dead
        network and park the scan in an endless pause.  Callers must check
        this and skip overwatching entirely rather than block forever.

        ``fping`` is preferred because it is already a required pipeline tool
        (and ``ping``/``iproute2`` are not guaranteed to be installed in every
        image); ``ping`` is used as a fallback.
        """
        return shutil.which("fping") is not None or shutil.which("ping") is not None

    # -- public API -------------------------------------------------------

    @property
    def is_paused(self) -> bool:
        return self._paused

    @property
    def consecutive_failures(self) -> int:
        return self._consecutive_failures

    async def ping_host(self, ip: str) -> bool:
        """Ping a single host.  Returns True if reachable.

        Uses ``fping`` when available (already present in the worker image as
        a required pipeline tool), falling back to the ``ping`` binary.
        """
        timeout_ms = max(1000, int(self.timeout * 1000))
        if shutil.which("fping") is not None:
            result = await run_tool(
                ["fping", "-c", "1", "-t", str(timeout_ms), ip],
                timeout=self.timeout + 1,
                label=f"fping {ip}",
            )
            return result.returncode == 0

        result = await run_tool(
            ["ping", "-c", "1", "-W", str(int(self.timeout)), ip],
            timeout=self.timeout + 1,
            label=f"ping {ip}",
        )
        return result.returncode == 0

    async def all_reachable(self) -> bool:
        """Return True only if ALL targets answer ping."""
        if not self.targets:
            return True
        results = await asyncio.gather(
            *[self.ping_host(ip) for ip in self.targets],
            return_exceptions=True,
        )
        return all(r is True for r in results)

    async def check(self, is_aborted: "Callable[[], bool]") -> None:
        """Block until the network is considered healthy again.

        If all targets fail ``fail_threshold`` times in a row, discovery is
        considered paused and this coroutine waits (sleeping ``interval``
        between checks) until all targets answer ``recover_threshold`` times
        in a row, or ``is_aborted()`` returns True.

        Raises
        ------
        _TaskCancelled
            If the task is cancelled while waiting.
        """
        if not self.targets:
            return
        if not self.available:
            log.warning("Network overwatch: no ping/fping binary found — overwatching disabled")
            return

        while True:
            reachable = await self.all_reachable()

            if reachable:
                self._consecutive_successes += 1
                self._consecutive_failures = 0
                if self._paused and self._consecutive_successes >= self.recover_threshold:
                    self._paused = False
                    log.info("Network overwatch: all targets reachable again, resuming discovery")
                    return
                if not self._paused:
                    return
            else:
                self._consecutive_successes = 0
                self._consecutive_failures += 1
                if not self._paused and self._consecutive_failures >= self.fail_threshold:
                    self._paused = True
                    log.warning(
                        "Network overwatch: all %d target(s) unreachable — pausing discovery",
                        len(self.targets),
                    )

            if self._paused:
                if is_aborted():
                    raise _TaskCancelled("Task cancelled during network overwatch pause")
                await asyncio.sleep(self.interval)
