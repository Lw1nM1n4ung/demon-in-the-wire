import xml.etree.ElementTree as ET
import sys

def nmap_xml_to_custom_format(xml_file_path):
    """
    Parses an Nmap XML file and prints host IP and a comma-separated list of open ports
    in the format: |IP_ADDRESS | PORT/PROTOCOL,PORT/PROTOCOL |
    """
    try:
        # Parse the XML file
        tree = ET.parse(xml_file_path)
        root = tree.getroot()

        # Iterate over all 'host' elements in the XML
        for host in root.findall('host'):
            ip_address = None
            open_ports = []

            # 1. Get the IP Address
            # Try to find the primary address
            address_element = host.find("address[@addrtype='ipv4']")
            if address_element is not None:
                ip_address = address_element.get('addr')
            else:
                # Fallback to general address if specific IPv4 isn't found
                general_address = host.find('address')
                if general_address is not None:
                    ip_address = general_address.get('addr')

            # Skip hosts without a detectable IP address
            if not ip_address:
                continue

            # 2. Get the Open Ports
            ports_element = host.find('ports')
            if ports_element is not None:
                # Iterate over 'port' elements and check for state 'open'
                for port in ports_element.findall('port'):
                    state = port.find('state')
                    # Check if the port state is 'open'
                    if state is not None and state.get('state') == 'open':
                        port_id = port.get('portid')
                        protocol = port.get('protocol')
                        open_ports.append(f"{port_id}/{protocol}")

            # 3. Format and Print the Output
            ports_str = ','.join(open_ports)
            print(f"|{ip_address} | {ports_str} |")

    except FileNotFoundError:
        print(f"Error: The file '{xml_file_path}' was not found.")
        sys.exit(1)
    except ET.ParseError:
        print(f"Error: Failed to parse '{xml_file_path}'. Check if it's a valid Nmap XML file.")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

# --- Execution Block ---
if __name__ == "__main__":
    # Check if a file path was provided as a command-line argument
    if len(sys.argv) < 2:
        print("Usage: python script_name.py <path/to/nmap_output.xml>")
        sys.exit(1)

    xml_file = sys.argv[1]
    nmap_xml_to_custom_format(xml_file)
