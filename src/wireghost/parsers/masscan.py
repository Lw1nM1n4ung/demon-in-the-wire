"""Parser for masscan XML output."""
from __future__ import annotations
from defusedxml import ElementTree as ET  # safe XML parser (prevents XXE)
from collections import defaultdict
from pathlib import Path
from wireghost.models.scan import Host, Port

def parse_masscan_xml(xml_path: Path) -> list[Host]:
    """Parse masscan XML into Host objects. No service detection -- ports only.
    Returns empty list on missing/malformed file.
    """
    try:
        tree = ET.parse(xml_path)
    except (FileNotFoundError, ET.ParseError):
        return []

    root = tree.getroot()
    ip_ports: dict[str, list[Port]] = defaultdict(list)

    for host_el in root.findall("host"):
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")
        if not ip:
            continue
        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            state = state_el.get("state", "open") if state_el is not None else "open"
            if state != "open":
                continue
            ip_ports[ip].append(Port(
                number=int(port_el.get("portid", "0")),
                protocol=port_el.get("protocol", "tcp"),
                state="open",
            ))

    return [Host(ip=ip, ports=ports) for ip, ports in sorted(ip_ports.items())]
