import argparse
import xml.etree.ElementTree as ET
from openpyxl import Workbook

def extract_host_identifier(host_elem):
    for addr in host_elem.findall('address'):
        if addr.get('addrtype') == 'ipv4':
            return addr.get('addr')
    for addr in host_elem.findall('address'):
        if addr.get('addrtype') == 'ipv6':
            return addr.get('addr')
    # fallback to hostname
    hostnames = host_elem.find('hostnames')
    if hostnames is not None:
        hn = hostnames.find('hostname')
        if hn is not None and hn.get('name'):
            return hn.get('name')
    return 'unknown'

def extract_ports_detailed(host_elem):
    ports_info = []
    ports_elem = host_elem.find('ports')
    if ports_elem is None:
        return ports_info

    for port in ports_elem.findall('port'):
        portid = port.get('portid')
        protocol = port.get('protocol')
        state_elem = port.find('state')
        service_elem = port.find('service')
        state = state_elem.get('state') if state_elem is not None else 'unknown'
        service = service_elem.get('name') if service_elem is not None else ''
        ports_info.append({
            'port': portid,
            'protocol': protocol,
            'state': state,
            'service': service
        })
    return ports_info

def convert(xml_input, xlsx_output):
    tree = ET.parse(xml_input)
    root = tree.getroot()

    wb = Workbook()
    ws_summary = wb.active
    ws_summary.title = "Hosts and Ports"
    ws_details = wb.create_sheet("Detailed Ports")

    # Headers
    ws_summary.append(["Hosts", "Open Ports"])
    ws_details.append(["Host", "Port", "Protocol", "State", "Service"])

    for host in root.findall('host'):
        status = host.find('status')
        if status is not None and status.get('state') != 'up':
            continue

        host_ip = extract_host_identifier(host)
        ports_detailed = extract_ports_detailed(host)

        # Collect open ports only for summary
        open_ports = [
            f"{p['port']}/{p['protocol']}"
            for p in ports_detailed if p['state'] == 'open'
        ]
        ports_str = ",".join(open_ports)
        ws_summary.append([host_ip, ports_str])

        # Add all ports (open, closed, etc.) to details
        for p in ports_detailed:
            ws_details.append([
                host_ip, p['port'], p['protocol'], p['state'], p['service']
            ])

    wb.save(xlsx_output)
    print(f"Excel file saved: {xlsx_output}")

def main():
    parser = argparse.ArgumentParser(description="Convert Nmap XML to Excel with 2 sheets.")
    parser.add_argument("-i", "--input", required=True, help="Input Nmap XML file")
    parser.add_argument("-o", "--output", required=True, help="Output Excel (.xlsx) file")
    args = parser.parse_args()

    convert(args.input, args.output)

if __name__ == "__main__":
    main()
