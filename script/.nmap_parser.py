#!/usr/bin/env python3
import sys
import xml.etree.ElementTree as ET

def main(xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Get IP address
    ip_elem = root.find('.//address[@addrtype="ipv4"]')
    if ip_elem is None:
        print("Error: No IP address found in XML")
        sys.exit(1)
    ip = ip_elem.get('addr')

    # Get open ports
    ports = []
    for port in root.findall('.//port'):
        state = port.find('state')
        if state is not None and state.get('state') == 'open':
            ports.append(port.get('portid'))

    if not ports:
        print("No open ports found")
        sys.exit(1)

    # Generate command
    command = f"nmap -p{','.join(ports)} -sC -sV -Pn {ip} -oA /root/output/tmp/nmap_vuln_scan{ip}"
    print(command)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <nmap_xml_file>")
        sys.exit(1)
    main(sys.argv[1])

