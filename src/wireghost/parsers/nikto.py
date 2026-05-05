"""Nikto JSON parser — maps Nikto findings to the Finding dataclass."""

from __future__ import annotations

import json
import re
from pathlib import Path
from wireghost.models.finding import Finding
from wireghost.models.severity import Severity

_CRITICAL_RE = re.compile(
    r"remote\s+code\s+exec|command\s+exec|arbitrary\s+file"
    r"|shell|backdoor|rootkit",
    re.IGNORECASE,
)
_HIGH_RE = re.compile(
    r"sql\s+inject|xss|cross.site\s+script|csrf"
    r"|file\s+inclusion|directory\s+traversal|upload|rce|rfi|lfi",
    re.IGNORECASE,
)
_MEDIUM_RE = re.compile(
    r"directory\s+list|default\s+file|server\s+version|outdated"
    r"|ssl|hsts|clickjack|x-frame|anti-clickjack|phpinfo"
    r"|default\s+install|default\s+page|mod_negotiation",
    re.IGNORECASE,
)
_LOW_RE = re.compile(
    r"information\s+disclos|header|cookie|banner|x-powered-by"
    r"|server\s+leak|etag|allowed\s+http\s+method",
    re.IGNORECASE,
)


def _infer_severity(msg: str) -> Severity:
    if _CRITICAL_RE.search(msg):
        return Severity.CRITICAL
    if _HIGH_RE.search(msg):
        return Severity.HIGH
    if _MEDIUM_RE.search(msg):
        return Severity.MEDIUM
    if _LOW_RE.search(msg):
        return Severity.LOW
    return Severity.INFO


def _parse_vuln(vuln: dict, host_ip: str, port: str, protocol: str) -> Finding | None:
    nikto_id = vuln.get("id", "")
    msg = vuln.get("msg", "")
    if not nikto_id and not msg:
        return None

    url_path = vuln.get("url", "/")
    method = vuln.get("method", "GET")
    refs = vuln.get("references", "")

    template_id = f"NIKTO-{nikto_id}" if nikto_id else ""
    severity = _infer_severity(msg)

    full_url = f"{protocol}://{host_ip}:{port}{url_path}" if url_path else ""
    curl_cmd = f"curl -X {method} '{full_url}'" if full_url else ""

    references: list[str] = []
    if refs:
        references = [r.strip() for r in refs.split(",") if r.strip()]

    return Finding(
        source="nikto",
        host=host_ip,
        port=port,
        protocol=protocol,
        severity=severity,
        title=msg[:200] if msg else template_id,
        description=msg,
        endpoint=url_path or "/",
        full_url=full_url,
        template_id=template_id,
        request=f"{method} {url_path}" if url_path else "",
        curl_command=curl_cmd,
        references=references,
    )


def parse_nikto_json(json_path: Path) -> list[Finding]:
    """Parse Nikto JSON output and return a list of Findings.

    Nikto JSON is a top-level array of host objects, each containing
    a ``vulnerabilities`` list.
    """
    try:
        raw = json_path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return []

    raw = raw.strip()
    if not raw:
        return []

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []

    hosts: list[dict] = []
    if isinstance(parsed, list):
        hosts = parsed
    elif isinstance(parsed, dict):
        hosts = [parsed]
    else:
        return []

    findings: list[Finding] = []
    seen: set[str] = set()

    for host_obj in hosts:
        if not isinstance(host_obj, dict):
            continue
        host_ip = host_obj.get("ip", "") or host_obj.get("host", "")
        port = str(host_obj.get("port", ""))
        protocol = "https" if port == "443" else "http"

        for vuln in host_obj.get("vulnerabilities", []):
            if not isinstance(vuln, dict):
                continue
            finding = _parse_vuln(vuln, host_ip, port, protocol)
            if finding is None:
                continue
            dedup_key = f"{finding.template_id}:{finding.endpoint}"
            if dedup_key not in seen:
                seen.add(dedup_key)
                findings.append(finding)

    return findings
