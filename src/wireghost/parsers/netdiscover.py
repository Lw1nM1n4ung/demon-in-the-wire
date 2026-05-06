"""Parse netdiscover -P (parsable) output."""

from __future__ import annotations


def parse_netdiscover(stdout: str) -> list[tuple[str, str, str]]:
    """Parse netdiscover -P stdout.

    Returns list of (ip, mac_address, vendor) tuples.
    """
    results: list[tuple[str, str, str]] = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("_") or line.startswith("IP"):
            continue
        parts = line.split("/")
        if len(parts) >= 2:
            ip = parts[0].strip()
            mac = parts[1].strip()
            vendor = parts[4].strip() if len(parts) >= 5 else ""
            if ip and mac:
                results.append((ip, mac, vendor))
    return results
