"""Parser for searchsploit JSON output — maps exploits to findings."""

from __future__ import annotations

import json
from pathlib import Path

from wireghost.models.finding import Finding
from wireghost.models.severity import Severity


def _classify_exploit_severity(title: str, etype: str) -> Severity:
    """Classify exploit severity based on title and type."""
    t = title.lower()
    e = etype.lower()

    # Remote code execution / buffer overflow → critical
    if any(kw in t for kw in ("remote code", "rce", "buffer overflow", "command injection")):
        return Severity.CRITICAL

    # Exploits (remote) → high
    if "remote" in e or "exploit" in e:
        return Severity.HIGH

    # Local exploits, privilege escalation → high
    if "local" in e or "privilege" in t or "escalation" in t:
        return Severity.HIGH

    # DoS → medium
    if "dos" in e or "denial" in t:
        return Severity.MEDIUM

    # Webapps → medium
    if "webapps" in e or "sql injection" in t or "xss" in t:
        return Severity.MEDIUM

    # Shellcode, info disclosure → low
    if "shellcode" in e or "disclosure" in t:
        return Severity.LOW

    return Severity.INFO


def parse_searchsploit_json(json_path: Path, host_ip: str = "") -> list[Finding]:
    """Parse searchsploit JSON output into Finding objects.

    searchsploit -j output format:
    {
      "RESULTS_EXPLOIT": [
        {
          "Title": "Apache 2.4.49 - Path Traversal",
          "EDB-ID": "50383",
          "Date_Published": "2021-10-05",
          "Author": "...",
          "Type": "webapps",
          "Platform": "multiple",
          "Path": "/usr/share/exploitdb/exploits/multiple/webapps/50383.py",
          "Codes": "CVE-2021-41773;..."
        }
      ],
      "RESULTS_SHELLCODE": [...]
    }

    searchsploit --nmap output is similar but grouped by service.
    """
    try:
        content = json_path.read_text(encoding="utf-8").strip()
    except (FileNotFoundError, OSError):
        return []
    if not content:
        return []

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    if not isinstance(data, dict):
        return []

    findings: list[Finding] = []
    seen: set[str] = set()  # dedupe by EDB-ID

    for section_key in ("RESULTS_EXPLOIT", "RESULTS_SHELLCODE"):
        results = data.get(section_key, [])
        if not isinstance(results, list):
            continue

        for item in results:
            if not isinstance(item, dict):
                continue

            edb_id = str(item.get("EDB-ID", "")).strip()
            title = item.get("Title", "").strip()
            if not title:
                continue

            # Dedupe
            if edb_id and edb_id in seen:
                continue
            if edb_id:
                seen.add(edb_id)

            exploit_type = item.get("Type", "")
            platform = item.get("Platform", "")
            codes = item.get("Codes", "")
            path = item.get("Path", "")
            date = item.get("Date_Published", "")

            # Extract CVE references
            refs: list[str] = []
            if codes:
                for code in codes.split(";"):
                    code = code.strip()
                    if code:
                        refs.append(code)
                        if code.startswith("CVE-"):
                            refs.append(f"https://nvd.nist.gov/vuln/detail/{code}")
            if edb_id:
                refs.append(f"https://www.exploit-db.com/exploits/{edb_id}")

            severity = _classify_exploit_severity(title, exploit_type)

            desc_parts = []
            if date:
                desc_parts.append(f"Published: {date}")
            if exploit_type:
                desc_parts.append(f"Type: {exploit_type}")
            if platform:
                desc_parts.append(f"Platform: {platform}")
            if path:
                desc_parts.append(f"Exploit path: {path}")

            findings.append(Finding(
                source="searchsploit",
                host=host_ip,
                port="",
                protocol="tcp",
                severity=severity,
                title=f"Exploit: {title}",
                description="\n".join(desc_parts),
                template_id=f"EDB-{edb_id}" if edb_id else "",
                references=refs,
                tags=[exploit_type, platform] if exploit_type else [],
            ))

    return findings
