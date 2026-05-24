"""Parse snmpwalk -OQn output into structured data."""

from __future__ import annotations


# Well-known OID prefixes for system info
_SYS_DESCR = ".1.3.6.1.2.1.1.1"
_SYS_CONTACT = ".1.3.6.1.2.1.1.4"
_SYS_NAME = ".1.3.6.1.2.1.1.5"
_SYS_LOCATION = ".1.3.6.1.2.1.1.6"
_IF_DESCR = ".1.3.6.1.2.1.2.2.1.2"
_IF_PHYS_ADDR = ".1.3.6.1.2.1.2.2.1.6"


def parse_snmpwalk(stdout: str) -> dict[str, str]:
    """Parse snmpwalk -OQn output into an OID→value dict.

    Returns a dict mapping OID strings to their values.
    Only captures system-info and interface OIDs to keep things lean.
    """
    results: dict[str, str] = {}
    interesting_prefixes = (
        _SYS_DESCR,
        _SYS_CONTACT,
        _SYS_NAME,
        _SYS_LOCATION,
        _IF_DESCR,
        _IF_PHYS_ADDR,
    )

    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("Timeout") or "=" not in line:
            continue
        oid, _, value = line.partition("=")
        oid = oid.strip()
        value = value.strip().strip('"')

        if any(oid.startswith(p) for p in interesting_prefixes):
            results[oid] = value

    return results


def extract_system_info(oid_map: dict[str, str]) -> dict[str, str]:
    """Extract human-readable system info from parsed OIDs."""
    info: dict[str, str] = {}
    for oid, val in oid_map.items():
        if oid.startswith(_SYS_DESCR):
            info["sysDescr"] = val
        elif oid.startswith(_SYS_CONTACT):
            info["sysContact"] = val
        elif oid.startswith(_SYS_NAME):
            info["sysName"] = val
        elif oid.startswith(_SYS_LOCATION):
            info["sysLocation"] = val
    return info
