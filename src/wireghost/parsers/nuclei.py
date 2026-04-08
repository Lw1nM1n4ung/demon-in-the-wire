"""Nuclei JSON / JSONL parser."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from wireghost.models.finding import Finding
from wireghost.models.severity import Severity
from wireghost.utils.network import extract_endpoint, safe_get

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _parse_item(item: dict) -> Finding | None:
    """Convert a single nuclei JSON object to a Finding.

    Returns *None* when the item lacks the required fields.
    """
    template_id = item.get("template-id", "")
    info_name = safe_get(item, ["info", "name"], default="")
    if not template_id and not info_name:
        return None

    host_url = item.get("host", "") or item.get("ip", "")
    if not host_url:
        return None

    # IP and port from explicit fields or URL.
    ip = item.get("ip", "")
    port_str = str(item.get("port", ""))
    protocol = item.get("scheme", "")

    matched_at = item.get("matched-at", host_url)
    endpoint = extract_endpoint(matched_at) if matched_at else "/"

    # Derive port/protocol from matched-at URL if not explicitly set.
    if matched_at:
        parsed = urlparse(matched_at)
        if not ip and parsed.hostname:
            ip = parsed.hostname
        if not port_str and parsed.port:
            port_str = str(parsed.port)
        if not protocol and parsed.scheme:
            protocol = parsed.scheme

    # Severity.
    raw_sev = safe_get(item, ["info", "severity"], default="unknown")
    severity = _SEVERITY_MAP.get(str(raw_sev).lower(), Severity.UNKNOWN)

    title = str(info_name) if info_name else template_id

    description = safe_get(item, ["info", "description"], default="")
    if description == "N/A":
        description = ""

    # References may be a list or a single string.
    raw_refs = safe_get(item, ["info", "reference"], default=[])
    if isinstance(raw_refs, str):
        references = [raw_refs] if raw_refs else []
    elif isinstance(raw_refs, list):
        references = [str(r) for r in raw_refs if r]
    else:
        references = []

    raw_tags = safe_get(item, ["info", "tags"], default=[])
    if isinstance(raw_tags, str):
        tags = [t.strip() for t in raw_tags.split(",") if t.strip()]
    elif isinstance(raw_tags, list):
        tags = [str(t) for t in raw_tags]
    else:
        tags = []

    # Evidence data
    request = str(item.get("request", ""))
    response = str(item.get("response", ""))
    if len(response) > 2000:
        response = response[:2000] + "\n\n[TRUNCATED]"
    curl_cmd = str(item.get("curl-command", ""))

    # Classification
    classification = safe_get(item, ["info", "classification"], default={})
    cvss = ""
    cwe = ""
    cve = ""
    if isinstance(classification, dict):
        cvss = str(classification.get("cvss-metrics", "") or "")
        cwe_list = classification.get("cwe-id") or []
        if isinstance(cwe_list, list):
            cwe = ", ".join(str(c) for c in cwe_list if c)
        elif cwe_list:
            cwe = str(cwe_list)
        cve_list = classification.get("cve-id") or []
        if isinstance(cve_list, list):
            cve = ", ".join(str(c) for c in cve_list if c)
        elif cve_list:
            cve = str(cve_list)

    return Finding(
        source="nuclei",
        host=ip,
        port=port_str,
        protocol=protocol,
        severity=severity,
        title=title,
        description=str(description),
        endpoint=endpoint,
        full_url=matched_at,
        template_id=template_id,
        matched_at=matched_at,
        references=references,
        tags=tags,
        request=request,
        response=response,
        curl_command=curl_cmd,
        cvss=cvss,
        cwe=cwe,
        cve=cve,
    )


def parse_nuclei_json(json_path: Path) -> list[Finding]:
    """Parse nuclei output (JSON array **or** JSONL).

    Returns an empty list on missing file, empty file, or
    malformed content.
    """
    try:
        raw = json_path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return []

    raw = raw.strip()
    if not raw:
        return []

    items: list[dict] = []

    # Try JSON array first.
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            items = parsed
        elif isinstance(parsed, dict):
            items = [parsed]
    except json.JSONDecodeError:
        # Fall back to JSONL (one object per line).
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    items.append(obj)
            except json.JSONDecodeError:
                continue

    findings: list[Finding] = []
    for item in items:
        finding = _parse_item(item)
        if finding is not None:
            findings.append(finding)

    return findings
