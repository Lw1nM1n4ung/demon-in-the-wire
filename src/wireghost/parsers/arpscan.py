"""Parse arp-scan --plain output into (ip, mac, vendor) tuples."""

from __future__ import annotations


def parse_arpscan(stdout: str) -> list[tuple[str, str, str]]:
    """Parse arp-scan --plain stdout.

    Returns list of (ip, mac_address, vendor) tuples.
    """
    results: list[tuple[str, str, str]] = []
    for line in stdout.strip().splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            ip = parts[0].strip()
            mac = parts[1].strip()
            vendor = parts[2].strip() if len(parts) >= 3 else ""
            if ip and mac:
                results.append((ip, mac, vendor))
    return results
