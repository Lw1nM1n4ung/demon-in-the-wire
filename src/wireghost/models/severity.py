"""Severity enum, ordering, colors, and nmap vuln categorization."""

from __future__ import annotations

import enum
import re


class Severity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
    Severity.UNKNOWN: 5,
}

SEVERITY_COLORS: dict[Severity, tuple[int, int, int]] = {
    Severity.CRITICAL: (178, 34, 34),
    Severity.HIGH: (255, 0, 0),
    Severity.MEDIUM: (255, 140, 0),
    Severity.LOW: (255, 215, 0),
    Severity.INFO: (100, 149, 237),
    Severity.UNKNOWN: (128, 128, 128),
}

SEVERITY_HEX: dict[Severity, str] = {
    sev: "#{:02X}{:02X}{:02X}".format(*rgb)
    for sev, rgb in SEVERITY_COLORS.items()
}

# --- keyword sets for nmap vuln categorization ---

_CRITICAL_KEYWORDS = re.compile(
    r"shellshock|heartbleed|eternalblue|bluekeep"
    r"|cve-2014-6271|cve-2014-0160|ms17-010",
    re.IGNORECASE,
)

_HIGH_KEYWORDS = re.compile(
    r"vuln|exploit|rce|remote[- ]code[- ]execution"
    r"|sqli|xss|injection|buffer[- ]overflow|privilege",
    re.IGNORECASE,
)

_MEDIUM_KEYWORDS = re.compile(
    r"weak|default|info-disclosure|information-disclosure"
    r"|enum|brute|fuzz",
    re.IGNORECASE,
)


def categorize_nmap_vuln(script_id: str, output: str) -> Severity:
    """Categorize an nmap script result into a Severity level.

    Checks script_id and output against merged keyword lists
    from end.py and port_vuln.py.
    """
    combined = f"{script_id} {output}"

    if _CRITICAL_KEYWORDS.search(combined):
        return Severity.CRITICAL
    if _HIGH_KEYWORDS.search(combined):
        return Severity.HIGH
    if _MEDIUM_KEYWORDS.search(combined):
        return Severity.MEDIUM
    return Severity.INFO
