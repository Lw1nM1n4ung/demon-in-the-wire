import xml.etree.ElementTree as ET
from docx import Document
import sys
import os

def create_docx_report_from_xml(xml_file_path, output_dir):
    """
    Parses Nmap XML and generates a DOCX report, combining Port and Protocol
    into a single 'Port/Protocol' column, and saves it to the specified directory.
    """
    
    # 1. Construct the output file path
    base_name = os.path.splitext(os.path.basename(xml_file_path))[0]
    docx_output_path = os.path.join(output_dir, f"{base_name}_report.docx")

    # Ensure the output directory exists
    try:
        os.makedirs(output_dir, exist_ok=True)
    except OSError as e:
        print(f"❌ Error: Could not create output directory {output_dir}. {e}")
        return

    try:
        # 2. Parse the XML file
        tree = ET.parse(xml_file_path)
        root = tree.getroot()
    except FileNotFoundError:
        print(f"❌ Error: Nmap XML file not found at {xml_file_path}")
        return
    except ET.ParseError:
        print(f"❌ Error: Could not parse XML from {xml_file_path}")
        return
    except Exception as e:
        print(f"An unexpected error occurred during parsing: {e}")
        return

    # 3. Create the Word Document
    document = Document()
    document.add_heading('Nmap Scan Analysis Report', 0)

    # Add general scan information
    scan_args = root.attrib.get('args', 'N/A')
    document.add_paragraph(f"Scan Arguments: {scan_args}")

    runstats = root.find('runstats')
    if runstats is not None:
        finished = runstats.find('finished')
        if finished is not None:
            time_str = finished.attrib.get('timestr', 'N/A')
            document.add_paragraph(f"Scan Completed: {time_str}")
    
    document.add_paragraph("-" * 50)
    
    # 4. Iterate through hosts and build report
    host_count = 0
    for host_element in root.findall('host'):
        host_count += 1
        
        # Get IP address and state
        address_element = host_element.find('address')
        ip_address = address_element.attrib.get('addr', 'N/A') if address_element is not None else 'N/A'
        status = host_element.find('status').attrib.get('state', 'Unknown')
        
        # Get hostname
        hostname_element = host_element.find('hostnames/hostname')
        hostname = hostname_element.attrib.get('name', 'N/A') if hostname_element is not None else 'N/A'
        
        document.add_heading(f'Host {host_count}: {ip_address} ({hostname})', level=1)
        
        p = document.add_paragraph()
        p.add_run('Status: ').bold = True
        p.add_run(status.upper())
        
        # --- Ports and Services Table ---
        ports_element = host_element.find('ports')
        if ports_element is not None:
            document.add_heading('Open Ports', level=2)
            
            # Table for ports (4 columns)
            table = document.add_table(rows=1, cols=4)
            table.style = 'Light Shading Accent 1'
            
            # Table Header
            hdr_cells = table.rows[0].cells
            hdr_cells[0].text = 'Port/Protocol'
            hdr_cells[1].text = 'Port Status'
            hdr_cells[2].text = 'Service'
            hdr_cells[3].text = 'Version'
            
            for port_element in ports_element.findall('port'):
                state = port_element.find('state').attrib.get('state', 'N/A')
                
                # Only include relevant ports
                if state in ['open', 'open|filtered']:
                    port_num = port_element.attrib.get('portid', 'N/A')
                    protocol = port_element.attrib.get('protocol', 'N/A')
                    
                    service_element = port_element.find('service')
                    service_name = service_element.attrib.get('name', 'N/A') if service_element is not None else 'N/A'
                    service_version = service_element.attrib.get('version', 'N/A') if service_element is not None and service_element.attrib.get('version') else 'N/A'

                    # COMBINED FORMAT: 22/tcp
                    port_protocol_combo = f"{port_num}/{protocol}"

                    row_cells = table.add_row().cells
                    row_cells[0].text = port_protocol_combo
                    row_cells[1].text = state
                    row_cells[2].text = service_name
                    row_cells[3].text = service_version

        # Add a page break after each host
        document.add_page_break() 

    # 5. Save the DOCX document
    document.save(docx_output_path)
    print(f"\n✅ Nmap Report for {host_count} hosts successfully generated.")
    print(f"   Output file: {docx_output_path}")

# ----------------- EXECUTION FROM COMMAND LINE -----------------

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 main.py <input_xml_file_path> <output_directory>")
        print("Example: python3 main.py nmap.xml /root/output")
        sys.exit(1)
    
    # Get file paths from command-line arguments
    input_file = sys.argv[1]
    output_dir = sys.argv[2]
    
    # Check if input file exists
    if not os.path.exists(input_file):
        print(f"❌ Error: Input XML file not found at {input_file}")
        sys.exit(1)

    create_docx_report_from_xml(input_file, output_dir)
