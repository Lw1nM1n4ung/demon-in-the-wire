"""Parser for OpenVAS/Greenbone XML report output."""
from __future__ import annotations
import xml.etree.ElementTree as ET
from pathlib import Path
from wireghost.models.finding import Finding
from wireghost.models.severity import Severity


def _threat_to_severity(threat: str, cvss: float) -> Severity:
    if cvss >= 9.0:
        return Severity.CRITICAL
    t = threat.lower()
    if t == "high":
        return Severity.HIGH
    if t == "medium":
        return Severity.MEDIUM
    if t == "low":
        return Severity.LOW
    return Severity.INFO


def parse_openvas_xml(xml_path: Path, host_ip: str = "") -> list[Finding]:
    """Parse OpenVAS XML report into Finding objects."""
    try:
        root = ET.parse(xml_path).getroot()
    except (FileNotFoundError, ET.ParseError):
        return []

    findings: list[Finding] = []
    # Handle both <report><results><result> and <report><report><results><result>
    results = root.findall(".//results/result")

    for result in results:
        host_el = result.find("host")
        host = host_el.text.strip() if host_el is not None and host_el.text else host_ip

        port_el = result.find("port")
        port_str = port_el.text.strip() if port_el is not None and port_el.text else ""
        # port format: "80/tcp" or "general/tcp"
        port_num = ""
        protocol = "tcp"
        if "/" in port_str:
            parts = port_str.split("/")
            port_num = parts[0] if parts[0] != "general" else ""
            protocol = parts[1] if len(parts) > 1 else "tcp"

        nvt = result.find("nvt")
        title = ""
        oid = ""
        cvss = 0.0
        family = ""
        if nvt is not None:
            name_el = nvt.find("name")
            title = name_el.text.strip() if name_el is not None and name_el.text else ""
            oid = nvt.get("oid", "")
            severity_el = nvt.find("severity")
            if severity_el is not None and severity_el.text:
                try:
                    cvss = float(severity_el.text)
                except ValueError:
                    pass
            # Fallback to cvss_base
            if cvss == 0.0:
                cvss_el = nvt.find("cvss_base")
                if cvss_el is not None and cvss_el.text:
                    try:
                        cvss = float(cvss_el.text)
                    except ValueError:
                        pass
            family_el = nvt.find("family")
            family = family_el.text.strip() if family_el is not None and family_el.text else ""

        threat_el = result.find("threat")
        threat = threat_el.text.strip() if threat_el is not None and threat_el.text else "Log"

        desc_el = result.find("description")
        description = desc_el.text.strip() if desc_el is not None and desc_el.text else ""

        severity = _threat_to_severity(threat, cvss)

        # Extract CVE references
        refs: list[str] = []
        for ref_el in result.findall(".//refs/ref"):
            ref_type = ref_el.get("type", "")
            ref_id = ref_el.get("id", "")
            if ref_type == "cve" and ref_id:
                refs.append(ref_id)
                refs.append(f"https://nvd.nist.gov/vuln/detail/{ref_id}")
            elif ref_id:
                refs.append(ref_id)

        if not title:
            continue

        findings.append(Finding(
            source="openvas",
            host=host,
            port=port_num,
            protocol=protocol,
            severity=severity,
            title=title,
            description=description,
            template_id=oid,
            references=refs,
            tags=[family] if family else [],
        ))

    return findings
