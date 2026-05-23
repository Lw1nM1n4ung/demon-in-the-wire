"""Parser for WPScan JSON output."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from wireghost.models.finding import Finding
from wireghost.models.severity import Severity


def _extract_port(url: str) -> str:
    """Extract port from *url*, defaulting to 443 for https, 80 otherwise."""
    if not url:
        return "80"
    try:
        p = urlparse(url)
        if p.port:
            return str(p.port)
        return "443" if p.scheme == "https" else "80"
    except Exception:
        return "80"


def parse_wpscan_json(json_path: Path, host_ip: str = "") -> list[Finding]:
    """Parse WPScan JSON output into Finding objects."""
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []
    if not isinstance(data, dict):
        return []

    findings: list[Finding] = []
    target_url = data.get("target_url", "")
    port = _extract_port(target_url)

    # WordPress version
    wp_ver = data.get("version", {})
    if wp_ver and isinstance(wp_ver, dict):
        ver_num = wp_ver.get("number", "")
        if ver_num:
            findings.append(Finding(
                source="wpscan", host=host_ip, port=port, protocol="tcp",
                severity=Severity.INFO,
                title=f"WordPress Version: {ver_num}",
                description=f"WordPress {ver_num} detected at {target_url}",
                full_url=target_url,
            ))
            # Version vulnerabilities
            for vuln in wp_ver.get("vulnerabilities", []):
                findings.append(_vuln_to_finding(vuln, host_ip, target_url))

    # Plugins
    plugins = data.get("plugins", {})
    if isinstance(plugins, dict):
        for name, info in plugins.items():
            ver = info.get("version", {})
            ver_num = ver.get("number", "") if isinstance(ver, dict) else ""
            findings.append(Finding(
                source="wpscan", host=host_ip, port=port, protocol="tcp",
                severity=Severity.INFO,
                title=f"WP Plugin: {name}" + (f" {ver_num}" if ver_num else ""),
                description=f"WordPress plugin '{name}' detected.",
                full_url=target_url,
            ))
            for vuln in info.get("vulnerabilities", []):
                findings.append(_vuln_to_finding(vuln, host_ip, target_url, context=f"Plugin: {name}"))

    # Themes
    themes = data.get("themes", {}) or data.get("main_theme", {})
    if isinstance(themes, dict):
        # Could be single theme or dict of themes
        if "style_name" in themes:
            themes = {themes.get("style_name", "unknown"): themes}
        for name, info in themes.items():
            if not isinstance(info, dict):
                continue
            findings.append(Finding(
                source="wpscan", host=host_ip, port=port, protocol="tcp",
                severity=Severity.INFO,
                title=f"WP Theme: {name}",
                description=f"WordPress theme '{name}' detected.",
                full_url=target_url,
            ))
            for vuln in info.get("vulnerabilities", []):
                findings.append(_vuln_to_finding(vuln, host_ip, target_url, context=f"Theme: {name}"))

    # Users
    users = data.get("users", {})
    if isinstance(users, dict):
        for username, info in users.items():
            findings.append(Finding(
                source="wpscan", host=host_ip, port=port, protocol="tcp",
                severity=Severity.MEDIUM,
                title=f"WP User: {username}",
                description=f"WordPress user '{username}' enumerated.",
                full_url=target_url,
            ))

    # Interesting findings
    for item in data.get("interesting_findings", []):
        if isinstance(item, dict):
            url = item.get("url", "")
            entry_type = item.get("type", "")
            findings.append(Finding(
                source="wpscan", host=host_ip, port=port, protocol="tcp",
                severity=Severity.LOW,
                title=f"WP: {entry_type}" if entry_type else "WP: Interesting finding",
                description=item.get("to_s", url),
                full_url=url,
                references=[r.get("url", "") for r in item.get("references", {}).get("url", []) if isinstance(r, dict)] if isinstance(item.get("references"), dict) else [],
            ))

    return findings


def _vuln_to_finding(vuln: dict, host_ip: str, url: str, context: str = "") -> Finding:
    title = vuln.get("title", "Unknown Vulnerability")
    refs: list[str] = []
    ref_data = vuln.get("references", {})
    if isinstance(ref_data, dict):
        for key, vals in ref_data.items():
            if isinstance(vals, list):
                refs.extend(str(v) for v in vals)

    # Extract CVE
    cve = ""
    cves = ref_data.get("cve", []) if isinstance(ref_data, dict) else []
    if cves:
        cve = ", ".join(f"CVE-{c}" for c in cves)

    return Finding(
        source="wpscan", host=host_ip, port=port, protocol="tcp",
        severity=Severity.HIGH,
        title=f"WP Vuln: {title}",
        description=vuln.get("description", title),
        full_url=url,
        cve=cve,
        references=refs,
        raw_output=f"{context}\n{title}" if context else title,
    )
