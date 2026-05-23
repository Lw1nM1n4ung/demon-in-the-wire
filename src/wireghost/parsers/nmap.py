"""Nmap XML parser — port scans and vuln scans."""

from __future__ import annotations

from defusedxml import ElementTree as ET  # safe XML parser (prevents XXE)
from pathlib import Path

from wireghost.models.finding import Finding
from wireghost.models.scan import Host, Port, Service
from wireghost.models.severity import categorize_nmap_vuln


def parse_nmap_xml(xml_path: Path) -> list[Host]:
    """Parse nmap port-scan XML into a list of Host objects.

    Returns an empty list when the file is missing or the XML is
    malformed.
    """
    try:
        tree = ET.parse(xml_path)
    except (FileNotFoundError, ET.ParseError):
        return []

    root = tree.getroot()
    hosts: list[Host] = []

    for host_el in root.findall("host"):
        # --- address ---
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")

        # --- hostname ---
        hostname = ""
        hn_el = host_el.find("hostnames/hostname")
        if hn_el is not None:
            hostname = hn_el.get("name", "")

        # --- status ---
        status = "up"
        status_el = host_el.find("status")
        if status_el is not None:
            status = status_el.get("state", "up")

        # --- ports ---
        ports: list[Port] = []
        for port_el in host_el.findall("ports/port"):
            port_num = int(port_el.get("portid", "0"))
            protocol = port_el.get("protocol", "tcp")

            state = "open"
            state_el = port_el.find("state")
            if state_el is not None:
                state = state_el.get("state", "open")

            service: Service | None = None
            svc_el = port_el.find("service")
            if svc_el is not None:
                service = Service(
                    name=svc_el.get("name", ""),
                    product=svc_el.get("product", ""),
                    version=svc_el.get("version", ""),
                )

            ports.append(
                Port(
                    number=port_num,
                    protocol=protocol,
                    state=state,
                    service=service,
                    service_source='nmap' if service else '',
                )
            )

        # OS detection
        os_match = host_el.find("os/osmatch")
        os_info = ""
        if os_match is not None:
            os_info = os_match.get("name", "")

        hosts.append(
            Host(ip=ip, hostname=hostname, status=status, ports=ports, os=os_info)
        )

    return hosts


def parse_nmap_vuln_xml(xml_path: Path) -> list[Finding]:
    """Parse nmap --script=vuln XML into Finding objects."""
    try:
        tree = ET.parse(xml_path)
    except (FileNotFoundError, ET.ParseError):
        return []

    root = tree.getroot()
    findings: list[Finding] = []

    for host_el in root.findall("host"):
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")

        for port_el in host_el.findall("ports/port"):
            port_num = port_el.get("portid", "0")
            protocol = port_el.get("protocol", "tcp")

            for script_el in port_el.findall("script"):
                script_id = script_el.get("id", "")
                output = script_el.get("output", "")

                # Skip non-vulnerable / error / info-only results
                out_lower = output.lower()
                sid_lower = script_id.lower()

                # Skip error/negative results
                if any(skip in out_lower for skip in (
                    "couldn't find any",
                    "couldn\\'t find a file",
                    "error: script execution failed",
                    "error: missing a param",
                    "not vulnerable",
                    "no vuln",
                    "might be redirecting",
                )):
                    continue

                # Skip pure info scripts (not vulnerabilities)
                _INFO_SCRIPTS = {
                    "ssh-hostkey", "ssh-publickey-acceptance", "ssh-auth-methods",
                    "ssl-cert", "ssl-date", "http-title", "http-server-header",
                    "irc-botnet-channels",
                }
                if sid_lower in _INFO_SCRIPTS:
                    continue

                severity = categorize_nmap_vuln(script_id, output)

                findings.append(
                    Finding(
                        source="nmap_vuln",
                        host=ip,
                        port=port_num,
                        protocol=protocol,
                        severity=severity,
                        title=f"Nmap: {script_id}",
                        description=output,
                        script_id=script_id,
                        raw_output=output,
                    )
                )

    return findings


def extract_open_ports(xml_path: Path) -> list[tuple[str, int]]:
    """Return (ip, port_number) pairs for open ports only."""
    hosts = parse_nmap_xml(xml_path)
    pairs: list[tuple[str, int]] = []
    for host in hosts:
        for port in host.open_ports:
            pairs.append((host.ip, port.number))
    return pairs


def generate_vuln_command(xml_path: Path, output_base: Path) -> str | None:
    """Generate an nmap --script=vuln command string from scan results.

    Returns *None* when there are no hosts or no open ports.
    """
    hosts = parse_nmap_xml(xml_path)
    if not hosts:
        return None

    # Collect all open port numbers across all hosts.
    all_ports: set[int] = set()
    all_ips: list[str] = []
    for host in hosts:
        open_ports = host.open_ports
        if open_ports:
            all_ips.append(host.ip)
            for p in open_ports:
                all_ports.add(p.number)

    if not all_ports:
        return None

    port_csv = ",".join(str(p) for p in sorted(all_ports))
    ip_list = " ".join(all_ips)

    return (
        f"nmap --script=vuln -p {port_csv} "
        f"-oX {output_base} {ip_list}"
    )
