import xml.etree.ElementTree as ET
import sys
import requests
from typing import List, Dict, Any

# Disable urllib3 warnings about insecure requests (like self-signed certificates)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Set a reasonable timeout for the requests
TIMEOUT = 5

def find_all_open_ports(nmap_xml_file: str) -> List[Dict[str, Any]]:
    """
    Parses an Nmap XML file and extracts all open TCP ports.
    """
    open_ports = []
    
    try:
        tree = ET.parse(nmap_xml_file)
        root = tree.getroot()
    except FileNotFoundError:
        print(f"Error: File not found at '{nmap_xml_file}'")
        return []
    except ET.ParseError:
        print(f"Error: Failed to parse XML file at '{nmap_xml_file}'. Check file integrity.")
        return []

    # Iterate through all 'host' elements
    for host in root.findall('host'):
        address_element = host.find('address')
        if address_element is None:
            continue
            
        ip_address = address_element.get('addr')
        
        # Find the 'ports' section
        ports = host.find('ports')
        if ports is None:
            continue

        # Iterate through all 'port' elements
        for port in ports.findall('port'):
            state = port.find('state')
            # Only consider TCP ports that Nmap identified as 'open'
            if state is None or state.get('state') != 'open' or port.get('protocol') != 'tcp':
                continue

            port_id = port.get('portid')
            
            # Get the Nmap detected service name (for informational output)
            service_element = port.find('service')
            service_name = service_element.get('name', 'N/A') if service_element is not None else 'N/A'
            
            open_ports.append({
                'ip_address': ip_address,
                'port': port_id,
                'nmap_service': service_name
            })
                
    return open_ports

def check_web_service(ip: str, port: str) -> str:
    """
    Attempts HTTP and then HTTPS connection to determine the service type.
    
    Returns: 'http', 'https', or 'none'.
    """
    # 1. Attempt HTTP (http://IP:PORT)
    http_url = f"http://{ip}:{port}"
    try:
        r = requests.head(http_url, timeout=TIMEOUT, allow_redirects=True)
        if 200 <= r.status_code < 599:
             return 'http'
    except requests.exceptions.Timeout:
        pass
    except requests.exceptions.ConnectionError:
        pass
    except Exception:
        pass

    # 2. Attempt HTTPS (https://IP:PORT)
    https_url = f"https://{ip}:{port}"
    try:
        r = requests.head(https_url, timeout=TIMEOUT, allow_redirects=True, verify=False)
        if 200 <= r.status_code < 599:
             return 'https'
    except requests.exceptions.Timeout:
        pass
    except requests.exceptions.ConnectionError:
        pass
    except Exception:
        pass

    return 'none'


def scan_for_web_hosts(nmap_xml_file: str) -> List[Dict[str, Any]]:
    """
    Main function to orchestrate parsing and web service checking.
    """
    all_open_ports = find_all_open_ports(nmap_xml_file)
    web_hosts = []
    
    total_ports = len(all_open_ports)
    print(f"\nFound {total_ports} open TCP ports to test. This may take a moment...")
    
    for i, item in enumerate(all_open_ports):
        ip = item['ip_address']
        port = item['port']
        nmap_service = item['nmap_service']
        
        # Simple progress indicator
        sys.stdout.write(f"\rTesting port {i + 1}/{total_ports}: {ip}:{port}...")
        sys.stdout.flush()

        service_type = check_web_service(ip, port)
        
        if service_type != 'none':
            protocol_prefix = "https" if service_type == 'https' else "http"
            web_hosts.append({
                'ip_address': ip,
                'port': port,
                'protocol': service_type,
                'nmap_service': nmap_service,
                'url': f"{protocol_prefix}://{ip}:{port}"
            })
            
    print("\nTesting complete.")
    return web_hosts


def print_results(hosts: List[Dict[str, Any]], output_file: str = None):
    """
    Prints the extracted web host information and optionally saves URLs to a file.
    """
    if not hosts:
        print("\n="*80)
        print("No definitive web services found on the tested open ports.")
        print("="*80)
        return

    # --- Print to Console ---
    print("\n" + "="*80)
    print("Confirmed Web Hosts Found (Based on Successful HTTP/HTTPS Requests)")
    print("="*80)
    print(f"{'IP Address':<15} | {'Port':<6} | {'Protocol':<8} | {'Nmap Service':<15} | {'Confirmed URL':<30}")
    print("-" * 80)
    
    for host in hosts:
        print(f"{host['ip_address']:<15} | {host['port']:<6} | {host['protocol']:<8} | {host['nmap_service']:<15} | {host['url']:<30}")
    
    # --- Write to File ---
    if output_file:
        try:
            with open(output_file, 'w') as f:
                for host in hosts:
                    f.write(f"{host['url']}\n")
            print(f"\n✅ Successfully saved {len(hosts)} URLs to '{output_file}'")
        except IOError:
            print(f"\n❌ Error: Could not write to file '{output_file}'. Check permissions or path.")


# --- Main execution block ---
if __name__ == "__main__":
    # CHECK FOR TWO ARGUMENTS: NMAP_XML_FILE and OUTPUT_FILE
    if len(sys.argv) != 3:
        print("Usage: python script_name.py <nmap_xml_file> <output_txt_file>")
        print("Example: python web_finder.py scan_results.xml confirmed_urls.txt")
        sys.exit(1)

    # Assign arguments
    nmap_file = sys.argv[1]
    output_filename = sys.argv[2]
    
    # 1. Scan for web hosts
    confirmed_web_hosts = scan_for_web_hosts(nmap_file)
    
    # 2. Print the results AND save them to the specified file
    print_results(confirmed_web_hosts, output_file=output_filename)
