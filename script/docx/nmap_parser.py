#!/usr/bin/env python3
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

def main(xml_file):
    xml_path = Path(xml_file)
    if not xml_path.exists():
        print(f"Error: file not found: {xml_file}", file=sys.stderr)
        sys.exit(2)

    try:
        tree = ET.parse(str(xml_path))
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}", file=sys.stderr)
        sys.exit(3)

    # Nmap XML structure: host -> address (addrtype=ipv4) and ports/port
    ip = None
    for addr in root.findall(".//address"):
        if addr.get("addrtype") == "ipv4":
            ip = addr.get("addr")
            break
    if not ip:
        # Try hostname resolution inside nmap xml if present
        for host in root.findall(".//host"):
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr")
                    break
            if ip:
                break

    if not ip:
        print("Error: No IPv4 address found in XML.", file=sys.stderr)
        sys.exit(4)

    ports = []
    for port in root.findall(".//port"):
        state = port.find("state")
        if state is not None and state.get("state") == "open":
            portid = port.get("portid")
            if portid:
                ports.append(portid)

    if not ports:
        # nothing open -> nothing to run
        print(f"# {ip} - No open ports found")
        return

    # join ports safely (remove duplicates and sort numerically)
    try:
        unique_ports = sorted({int(p) for p in ports})
        port_list = ",".join(str(p) for p in unique_ports)
    except ValueError:
        # fallback if non-int ports somehow present
        port_list = ",".join(sorted(set(ports)))

    # make a safe filename for the run
    outbase = f"/root/output/tmp/nmap_vuln_scan_{ip}"
    # Print the command (one line) — caller can run it
    cmd = f"nmap --script=vuln -p{port_list} -sC -sV -Pn {ip} -oA \"{outbase}\""
    print(cmd)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <nmap_xml_file>", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])
