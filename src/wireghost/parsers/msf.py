"""Parser for Metasploit console spool/stdout output."""

from __future__ import annotations

import re

from wireghost.models.finding import Finding
from wireghost.models.severity import Severity

_MODULE_START = re.compile(r"^#\s*===MODULE:(.+?):(\d+)===$")
_RESULT_LINE = re.compile(
    r"^\[([+*!-])\]\s+"
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"(?::(\d+))?"
    r"\s*-?\s*(.*)"
)

_CRITICAL_KEYWORDS = {
    "vulnerable", "ms17-010", "bluekeep", "cve-2019-0708",
    "unauthenticated", "no authentication", "none auth",
    "rce", "remote code execution",
}
_HIGH_KEYWORDS = {
    "anonymous", "login successful", "default credential",
    "blank password", "open access", "world readable",
}
_NOISE_PREFIXES = (
    "scanned ", "connecting to ", "auxiliary module execution completed",
    "scanning target", "discover_host",
)


def _classify_severity(line: str, default: Severity) -> Severity:
    lower = line.lower()
    if any(kw in lower for kw in _CRITICAL_KEYWORDS):
        return Severity.CRITICAL
    if any(kw in lower for kw in _HIGH_KEYWORDS):
        return Severity.HIGH
    return default


def parse_msf_output(output: str, host_ip: str) -> list[Finding]:
    """Parse MSF spool/console output into Finding objects."""
    findings: list[Finding] = []
    seen: set[str] = set()
    current_module = ""
    current_port = ""

    for line in output.splitlines():
        line = line.strip()

        marker = _MODULE_START.match(line)
        if marker:
            current_module = marker.group(1)
            current_port = marker.group(2)
            continue

        if line.startswith("# ===END_MODULE==="):
            current_module = ""
            current_port = ""
            continue

        m = _RESULT_LINE.match(line)
        if not m:
            continue

        level = m.group(1)
        ip = m.group(2)
        port = m.group(3) or current_port
        message = m.group(4).strip()

        if not message or level == "-":
            continue

        if any(message.lower().startswith(p) for p in _NOISE_PREFIXES):
            continue

        if level == "+":
            severity = _classify_severity(message, Severity.HIGH)
        elif level == "!":
            severity = Severity.MEDIUM
        else:
            if not any(kw in message.lower() for kw in
                       ("version", "detected", "running", "server",
                        "os:", "build:", "domain:", "name:")):
                continue
            severity = Severity.INFO

        mod_short = current_module.split("/")[-1] if current_module else "msf"

        dedup_key = f"{ip}:{port}:{mod_short}:{message[:80]}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        findings.append(Finding(
            source="msf_scan",
            host=ip,
            port=port,
            protocol="tcp",
            severity=severity,
            title=f"MSF {mod_short}: {message[:100]}",
            description=message,
            template_id=current_module,
            raw_output=line,
        ))

    return findings
