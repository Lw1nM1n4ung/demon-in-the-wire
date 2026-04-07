import xml.etree.ElementTree as ET
from docx import Document
from docx.shared import Inches
import argparse
from datetime import datetime
import os

class NmapVulnReporter:
    def __init__(self):
        self.document = Document()
        
    def safe_text(self, text):
        """Convert None to empty string and ensure text is iterable"""
        if text is None:
            return ""
        return str(text)
        
    def parse_nmap_xml(self, nmap_file):
        """Parse Nmap XML file and extract port scan information"""
        try:
            tree = ET.parse(nmap_file)
            root = tree.getroot()
            
            scan_info = {
                'scan_start': root.get('start'),
                'scanner': 'nmap',
                'args': root.get('args'),
                'hosts': []
            }
            
            for host in root.findall('host'):
                host_info = {
                    'status': host.find('status').get('state') if host.find('status') is not None else 'unknown',
                    'addresses': [],
                    'hostnames': [],
                    'ports': []
                }
                
                # Get IP addresses
                for address in host.findall('address'):
                    host_info['addresses'].append({
                        'addr': address.get('addr'),
                        'type': address.get('addrtype')
                    })
                
                # Get hostnames
                for hostname in host.findall('hostnames/hostname'):
                    host_info['hostnames'].append({
                        'name': hostname.get('name'),
                        'type': hostname.get('type')
                    })
                
                # Get port information
                for port in host.findall('ports/port'):
                    service_elem = port.find('service')
                    port_info = {
                        'protocol': port.get('protocol'),
                        'portid': port.get('portid'),
                        'state': port.find('state').get('state') if port.find('state') is not None else 'unknown',
                        'service': service_elem.get('name') if service_elem is not None else 'unknown',
                        'product': service_elem.get('product') if service_elem is not None else '',
                        'version': service_elem.get('version') if service_elem is not None else ''
                    }
                    host_info['ports'].append(port_info)
                
                scan_info['hosts'].append(host_info)
            
            return scan_info
            
        except Exception as e:
            print(f"Error parsing Nmap XML: {e}")
            return None
    
    def parse_vuln_xml(self, vuln_file):
        """Parse Nmap vulnerability scan XML file"""
        try:
            tree = ET.parse(vuln_file)
            root = tree.getroot()
            
            vulnerabilities = []
            
            for host in root.findall('host'):
                host_ip = "Unknown"
                address_elem = host.find('address')
                if address_elem is not None:
                    host_ip = address_elem.get('addr', 'Unknown')
                
                for port in host.findall('ports/port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    
                    service_elem = port.find('service')
                    service_name = service_elem.get('name') if service_elem is not None else 'unknown'
                    
                    # Check for script results (vulnerabilities)
                    for script in port.findall('script'):
                        vuln_info = {
                            'host': host_ip,
                            'port': port_id,
                            'protocol': protocol,
                            'script_id': script.get('id', 'unknown'),
                            'output': script.get('output', ''),
                            'service': service_name
                        }
                        
                        # Parse table data if available
                        table_data = {}
                        for table in script.findall('table'):
                            table_data.update(self.parse_script_table(table))
                        
                        if table_data:
                            vuln_info['details'] = table_data
                        
                        vulnerabilities.append(vuln_info)
            
            return vulnerabilities
            
        except Exception as e:
            print(f"Error parsing vulnerability XML: {e}")
            return []
    
    def parse_script_table(self, table):
        """Parse Nmap script table data"""
        result = {}
        for elem in table:
            if elem.tag == 'elem':
                key = elem.get('key')
                if key:
                    result[key] = elem.text or ""
            elif elem.tag == 'table':
                key = elem.get('key')
                if key:
                    result[key] = self.parse_script_table(elem)
        return result
    
    def categorize_vulnerability(self, script_id, output):
        """Categorize vulnerabilities based on script ID and output"""
        script_id = script_id.lower() if script_id else ""
        output = output.lower() if output else ""
        
        # Critical vulnerabilities
        if any(keyword in script_id or keyword in output for keyword in [
            'shellshock', 'heartbleed', 'eternalblue', 'bluekeep',
            'cve-2014-6271', 'cve-2014-0160', 'ms17-010'
        ]):
            return 'critical'
        
        # High vulnerabilities
        elif any(keyword in script_id or keyword in output for keyword in [
            'vuln', 'exploit', 'rce', 'remote-code-execution', 'sqli',
            'xss', 'injection', 'buffer-overflow', 'privilege'
        ]):
            return 'high'
        
        # Medium vulnerabilities
        elif any(keyword in script_id or keyword in output for keyword in [
            'weak', 'default', 'info-disclosure', 'information-disclosure',
            'enum', 'brute', 'fuzz'
        ]):
            return 'medium'
        
        # Informational
        else:
            return 'info'
    
    def create_report(self, nmap_data, vuln_data, output_file):
        """Create DOCX report with Nmap port scan and vulnerability data"""
        
        # Title
        title = self.document.add_heading('Security Assessment Report', 0)
        self.document.add_paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.document.add_paragraph()
        
        # Executive Summary
        self.add_executive_summary(nmap_data, vuln_data)
        
        # Nmap Port Scan Results
        self.add_nmap_results(nmap_data)
        
        # Vulnerability Results
        self.add_vulnerability_results(vuln_data)
        
        # Recommendations
        self.add_recommendations(vuln_data)
        
        # Save document
        self.document.save(output_file)
        print(f"Report saved as: {output_file}")
    
    def add_executive_summary(self, nmap_data, vuln_data):
        """Add executive summary section"""
        heading = self.document.add_heading('Executive Summary', 1)
        
        # Count statistics
        total_hosts = len(nmap_data['hosts']) if nmap_data else 0
        open_ports = 0
        for host in nmap_data['hosts']:
            open_ports += len([p for p in host['ports'] if p['state'] == 'open'])
        
        total_vulns = len(vuln_data)
        
        # Categorize vulnerabilities
        critical_vulns = 0
        high_vulns = 0
        medium_vulns = 0
        info_vulns = 0
        
        for vuln in vuln_data:
            severity = self.categorize_vulnerability(vuln['script_id'], vuln['output'])
            if severity == 'critical':
                critical_vulns += 1
            elif severity == 'high':
                high_vulns += 1
            elif severity == 'medium':
                medium_vulns += 1
            else:
                info_vulns += 1
        
        summary = self.document.add_paragraph()
        summary.add_run('Scan Overview:\n').bold = True
        summary.add_run(f"• Total Hosts Scanned: {total_hosts}\n")
        summary.add_run(f"• Open Ports Found: {open_ports}\n")
        summary.add_run(f"• Total Vulnerabilities Found: {total_vulns}\n")
        summary.add_run(f"• Critical Vulnerabilities: {critical_vulns}\n")
        summary.add_run(f"• High Vulnerabilities: {high_vulns}\n")
        summary.add_run(f"• Medium Vulnerabilities: {medium_vulns}\n")
        summary.add_run(f"• Informational Findings: {info_vulns}\n")
        
        self.document.add_paragraph()
    
    def add_nmap_results(self, nmap_data):
        """Add Nmap port scan results section"""
        heading = self.document.add_heading('Port Scan Results', 1)
        
        if not nmap_data or not nmap_data['hosts']:
            self.document.add_paragraph('No port scan results available.')
            return
        
        # Scan information
        scan_info = self.document.add_paragraph()
        scan_info.add_run('Scan Information:\n').bold = True
        scan_info.add_run(f"Scanner: {nmap_data.get('scanner', 'Nmap')}\n")
        scan_info.add_run(f"Arguments: {nmap_data.get('args', 'N/A')}\n")
        scan_info.add_run(f"Scan Start: {nmap_data.get('scan_start', 'N/A')}\n")
        
        self.document.add_paragraph()
        
        # Host results
        for host in nmap_data['hosts']:
            # Host header
            host_heading = self.document.add_heading('Host Information', 2)
            
            # Host details
            host_para = self.document.add_paragraph()
            host_para.add_run('IP Addresses: ').bold = True
            host_para.add_run(', '.join([addr['addr'] for addr in host['addresses']]) + '\n')
            
            if host['hostnames']:
                host_para.add_run('Hostnames: ').bold = True
                host_para.add_run(', '.join([h['name'] for h in host['hostnames']]) + '\n')
            
            host_para.add_run('Status: ').bold = True
            host_para.add_run(host['status'] + '\n')
            
            # Port table (only open ports)
            open_ports = [p for p in host['ports'] if p['state'] == 'open']
            if open_ports:
                table = self.document.add_table(rows=1, cols=6)
                table.style = 'Light Grid Accent 1'
                
                # Header row
                hdr_cells = table.rows[0].cells
                hdr_cells[0].text = 'Port'
                hdr_cells[1].text = 'Protocol'
                hdr_cells[2].text = 'State'
                hdr_cells[3].text = 'Service'
                hdr_cells[4].text = 'Product'
                hdr_cells[5].text = 'Version'
                
                # Add port data
                for port in open_ports:
                    row_cells = table.add_row().cells
                    row_cells[0].text = self.safe_text(port['portid'])
                    row_cells[1].text = self.safe_text(port['protocol'])
                    row_cells[2].text = self.safe_text(port['state'])
                    row_cells[3].text = self.safe_text(port['service'])
                    row_cells[4].text = self.safe_text(port['product'])
                    row_cells[5].text = self.safe_text(port['version'])
            else:
                self.document.add_paragraph('No open ports found.')
            
            self.document.add_paragraph()
    
    def add_vulnerability_results(self, vuln_data):
        """Add vulnerability results section"""
        heading = self.document.add_heading('Vulnerability Assessment Results', 1)
        
        if not vuln_data:
            self.document.add_paragraph('No vulnerabilities found.')
            return
        
        # Group by severity
        vulns_by_severity = {'critical': [], 'high': [], 'medium': [], 'info': []}
        
        for vuln in vuln_data:
            severity = self.categorize_vulnerability(vuln['script_id'], vuln['output'])
            vulns_by_severity[severity].append(vuln)
        
        # Add vulnerabilities by severity
        for severity in ['critical', 'high', 'medium', 'info']:
            vulns = vulns_by_severity[severity]
            if vulns:
                severity_heading = self.document.add_heading(f'{severity.title()} Severity Findings', 2)
                
                for i, vuln in enumerate(vulns, 1):
                    # Vulnerability header
                    vuln_header = self.document.add_heading(f'Finding {i}: {vuln["script_id"]}', 3)
                    
                    # Vulnerability details
                    details = self.document.add_paragraph()
                    
                    details.add_run('Host: ').bold = True
                    details.add_run(f"{self.safe_text(vuln['host'])}\n")
                    
                    details.add_run('Port: ').bold = True
                    details.add_run(f"{self.safe_text(vuln['port'])}/{self.safe_text(vuln['protocol'])}\n")
                    
                    details.add_run('Service: ').bold = True
                    details.add_run(f"{self.safe_text(vuln['service'])}\n")
                    
                    details.add_run('Script ID: ').bold = True
                    details.add_run(f"{self.safe_text(vuln['script_id'])}\n")
                    
                    details.add_run('Severity: ').bold = True
                    details.add_run(f"{severity.title()}\n")
                    
                    details.add_run('Output: ').bold = True
                    details.add_run(f"{self.safe_text(vuln['output'])}\n")
                    
                    if 'details' in vuln and vuln['details']:
                        details.add_run('Details: ').bold = True
                        details.add_run(f"{self.format_details(vuln['details'])}\n")
                    
                    self.document.add_paragraph()
    
    def format_details(self, details, indent=0):
        """Format nested details dictionary"""
        result = []
        for key, value in details.items():
            if isinstance(value, dict):
                result.append("  " * indent + f"{key}:")
                result.append(self.format_details(value, indent + 1))
            else:
                result.append("  " * indent + f"{key}: {self.safe_text(value)}")
        return "\n".join(result)
    
    def add_recommendations(self, vuln_data):
        """Add recommendations section based on findings"""
        heading = self.document.add_heading('Recommendations', 1)
        
        recommendations = []
        
        # Analyze vulnerabilities and generate recommendations
        for vuln in vuln_data:
            script_id = vuln['script_id'].lower() if vuln['script_id'] else ""
            
            if 'http' in script_id or 'web' in vuln['service'].lower():
                rec = "• Implement web application firewall (WAF) rules"
                if rec not in recommendations:
                    recommendations.append(rec)
            
            if 'ssl' in script_id or 'tls' in script_id:
                rec = "• Update SSL/TLS configuration to disable weak ciphers"
                if rec not in recommendations:
                    recommendations.append(rec)
            
            if 'smb' in script_id or vuln['port'] in ['135', '139', '445']:
                rec = "• Harden SMB configuration and disable unnecessary services"
                if rec not in recommendations:
                    recommendations.append(rec)
            
            if 'ssh' in script_id or vuln['port'] == '22':
                rec = "• Implement SSH hardening (disable root login, use key-based auth)"
                if rec not in recommendations:
                    recommendations.append(rec)
        
        # Add general recommendations
        general_recs = [
            "• Apply security patches and updates regularly",
            "• Implement network segmentation",
            "• Conduct regular security assessments",
            "• Enable logging and monitoring",
            "• Follow principle of least privilege"
        ]
        
        recommendations.extend(general_recs)
        
        # Add to document
        for recommendation in recommendations:
            self.document.add_paragraph(recommendation, style='List Bullet')

def main():
    parser = argparse.ArgumentParser(description='Convert Nmap port scan and vulnerability XML to DOCX report')
    parser.add_argument('-n', '--nmap', required=True, help='Nmap port scan XML file')
    parser.add_argument('-v', '--vuln', required=True, help='Nmap vulnerability scan XML file')
    parser.add_argument('-o', '--output', default='security_report.docx', help='Output DOCX file')
    
    args = parser.parse_args()
    
    # Verify input files exist
    if not os.path.exists(args.nmap):
        print(f"Error: Nmap port scan file '{args.nmap}' not found")
        return
    
    if not os.path.exists(args.vuln):
        print(f"Error: Vulnerability scan file '{args.vuln}' not found")
        return
    
    # Create reporter
    reporter = NmapVulnReporter()
    
    # Parse data
    print("Parsing Nmap port scan XML...")
    nmap_data = reporter.parse_nmap_xml(args.nmap)
    
    print("Parsing Nmap vulnerability scan XML...")
    vuln_data = reporter.parse_vuln_xml(args.vuln)
    
    # Generate report
    print("Generating DOCX report...")
    reporter.create_report(nmap_data, vuln_data, args.output)
    
    print("Report generation completed!")
    print(f"Found {len(vuln_data)} vulnerabilities across {len(nmap_data['hosts']) if nmap_data else 0} hosts")

if __name__ == "__main__":
    main()
