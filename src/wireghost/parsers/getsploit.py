"""Parser for getsploit JSON output — maps Vulners API results to findings."""

from __future__ import annotations

import json

from wireghost.models.finding import Finding
from wireghost.models.severity import Severity


def _classify_exploit_severity(title: str, vuln_id: str) -> Severity:
    """Classify exploit severity based on title keywords and source."""
    t = title.lower()

    # Remote code execution / buffer overflow → critical
    if any(
        kw in t
        for kw in (
            "remote code",
            "rce",
            "buffer overflow",
            "command injection",
            "eternalblue",
            "bluekeep",
        )
    ):
        return Severity.CRITICAL

    # Known critical CVE patterns in titles
    if any(
        cve in t
        for cve in (
            "cve-2019-0708",
            "cve-2017-0144",
            "cve-2021-44228",
            "cve-2022-22965",
            "cve-2023-34362",
        )
    ):
        return Severity.CRITICAL

    # Metasploit exploits → high (they're weaponized)
    if vuln_id.startswith("MSF:"):
        return Severity.HIGH

    # Remote exploits → high
    if "remote" in t:
        return Severity.HIGH

    # Privilege escalation → high
    if any(kw in t for kw in ("privilege", "escalation", "local root")):
        return Severity.HIGH

    # DoS → medium
    if any(kw in t for kw in ("dos", "denial of service")):
        return Severity.MEDIUM

    # Webapps, SQLi, XSS → medium
    if any(
        kw in t
        for kw in (
            "sql injection",
            "xss",
            "cross-site",
            "path traversal",
            "directory traversal",
            "file inclusion",
        )
    ):
        return Severity.MEDIUM

    # Info disclosure → low
    if "disclosure" in t:
        return Severity.LOW

    return Severity.INFO


def parse_getsploit_json(output: str, host_ip: str = "") -> list[Finding]:
    """Parse getsploit -j JSON output into Finding objects.

    Getsploit JSON format::

        [
          {
            "id": "EDB-ID:50383",
            "title": "Apache 2.4.49 - Path Traversal and Remote Code Execution",
            "url": "https://vulners.com/exploit/EDB-ID:50383"
          },
          ...
        ]

    The ``id`` field encodes the source database:
      - ``EDB-ID:NNNNN`` — Exploit-DB
      - ``MSF:exploit/...`` — Metasploit
      - ``PACKETSTORM:NNNNN`` — Packetstorm Security
      - ``1337DAY-ID:NNNNN`` — 0day.today
    """
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []

    if not isinstance(data, list):
        return []

    findings: list[Finding] = []
    seen: set[str] = set()

    for item in data:
        if not isinstance(item, dict):
            continue

        vuln_id = str(item.get("id", "")).strip()
        title = item.get("title", "").strip()
        url = item.get("url", "").strip()

        if not title:
            continue

        # Deduplicate by Vulners ID
        if vuln_id and vuln_id in seen:
            continue
        if vuln_id:
            seen.add(vuln_id)

        # Extract CVE references from title (e.g., "CVE-2021-41773")
        refs: list[str] = []
        cve = ""
        import re

        for cve_match in re.finditer(r"(CVE-\d{4}-\d{4,})", title, re.IGNORECASE):
            cve_id = cve_match.group(1).upper()
            refs.append(cve_id)
            refs.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
            if not cve:
                cve = cve_id

        if url:
            refs.append(url)

        severity = _classify_exploit_severity(title, vuln_id)

        # Derive source database from the id prefix
        source_label = "vulners"
        if vuln_id.startswith("EDB-ID:"):
            source_label = "exploitdb"
        elif vuln_id.startswith("MSF:"):
            source_label = "metasploit"
        elif vuln_id.startswith("PACKETSTORM:"):
            source_label = "packetstorm"
        elif vuln_id.startswith("1337DAY-ID:"):
            source_label = "0day"

        findings.append(
            Finding(
                source="getsploit",
                host=host_ip,
                port="",
                protocol="tcp",
                severity=severity,
                title=f"Exploit ({source_label}): {title[:120]}",
                description=f"Vulners ID: {vuln_id}\nURL: {url}",
                template_id=vuln_id,
                cve=cve,
                references=refs,
                tags=[source_label],
            )
        )

    return findings
