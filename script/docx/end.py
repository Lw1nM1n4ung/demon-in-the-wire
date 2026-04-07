#!/usr/bin/env python3
"""
Enhanced Security Summary Reporter with Endpoint Details
"""

import sys
import xml.etree.ElementTree as ET
from pathlib import Path
import json
import argparse
from datetime import datetime
import os
from docx import Document
from docx.shared import RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from urllib.parse import urlparse

class EndpointSecuritySummaryReporter:
    def __init__(self):
        self.severity_colors = {
            'critical': RGBColor(178, 34, 34),    # Firebrick red
            'high': RGBColor(255, 0, 0),          # Red
            'medium': RGBColor(255, 140, 0),      # Dark orange
            'low': RGBColor(255, 215, 0),         # Gold
            'info': RGBColor(100, 149, 237),      # Cornflower blue
            'unknown': RGBColor(128, 128, 128)    # Gray
        }
    
    def parse_arguments(self):
        parser = argparse.ArgumentParser(
            description='Security Scan Summary Report with Endpoint Details',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog='''
Examples:
  # Full comprehensive report with endpoints
  python security_summary.py -n nmap.xml -v vuln.xml -j nuclei.json -o report.docx
  
  # Network-focused report  
  python security_summary.py -n nmap.xml -v vuln.xml -o network_report.docx
  
  # Web-focused report
  python security_summary.py -j nuclei.json -o web_report.docx
            '''
        )
        
        parser.add_argument('-n', '--nmap', nargs='+', help='Nmap XML file(s)')
        parser.add_argument('-v', '--vuln', nargs='+', help='Nmap vulnerability XML file(s)')
        parser.add_argument('-j', '--nuclei', nargs='+', help='Nuclei JSON file(s)')
        parser.add_argument('-o', '--output', required=True, help='Output DOCX file')
        parser.add_argument('-t', '--title', default='Security Assessment Summary Report', help='Report title')
        
        return parser.parse_args()
    
    def safe_get(self, obj, keys, default="N/A"):
        """Safely get nested dictionary values"""
        if isinstance(obj, dict):
            current = obj
            for key in keys:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    return default
            return current if current not in [None, ""] else default
        return default
    
    def extract_endpoint_from_url(self, url):
        """Extract clean endpoint from URL"""
        try:
            parsed = urlparse(url)
            endpoint = parsed.path
            if parsed.query:
                endpoint += '?' + parsed.query
            return endpoint if endpoint else '/'
        except:
            return url
    
    def parse_nuclei_scans(self, nuclei_files):
        """Parse Nuclei JSON files - handles both array and JSON lines format"""
        if not nuclei_files:
            return []
        
        all_vulnerabilities = []
        
        for nuclei_file in nuclei_files:
            print(f"📄 Processing Nuclei file: {os.path.basename(nuclei_file)}")
            
            if not os.path.exists(nuclei_file):
                print(f"  ❌ File not found")
                continue
                
            try:
                with open(nuclei_file, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    
                    if not content:
                        print("  ❌ File is empty")
                        continue
                    
                    file_vulnerabilities = []
                    
                    try:
                        # Try to parse as single JSON array first
                        data = json.loads(content)
                        
                        if isinstance(data, list):
                            print(f"  📊 Found JSON array with {len(data)} items")
                            for item in data:
                                if self.is_valid_nuclei_finding(item):
                                    vuln_info = self.create_nuclei_vuln_info(item)
                                    file_vulnerabilities.append(vuln_info)
                            
                        elif isinstance(data, dict):
                            print("  📊 Found single JSON object")
                            if self.is_valid_nuclei_finding(data):
                                vuln_info = self.create_nuclei_vuln_info(data)
                                file_vulnerabilities.append(vuln_info)
                        
                    except json.JSONDecodeError:
                        # If single JSON parse fails, try JSON lines format
                        print("  🔄 Trying JSON lines format...")
                        lines = content.split('\n')
                        for line in lines:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                item = json.loads(line)
                                if self.is_valid_nuclei_finding(item):
                                    vuln_info = self.create_nuclei_vuln_info(item)
                                    file_vulnerabilities.append(vuln_info)
                            except json.JSONDecodeError:
                                continue
                    
                    # Add file-specific vulnerabilities
                    all_vulnerabilities.extend(file_vulnerabilities)
                    print(f"  ✅ Added {len(file_vulnerabilities)} vulnerabilities")
                
            except Exception as e:
                print(f"  ❌ Error reading file: {e}")
        
        print(f"🎯 Total Nuclei vulnerabilities: {len(all_vulnerabilities)}")
        return all_vulnerabilities
    
    def is_valid_nuclei_finding(self, data):
        """Check if Nuclei finding is valid"""
        if not isinstance(data, dict):
            return False
        
        # Check for required Nuclei fields
        has_template_id = bool(data.get('template-id'))
        has_info_name = bool(data.get('info', {}).get('name'))
        has_host = bool(data.get('host') or data.get('ip'))
        
        return (has_template_id or has_info_name) and has_host
    
    def create_nuclei_vuln_info(self, data):
        """Create standardized vulnerability info from Nuclei data"""
        host = self.safe_get(data, ['host']) or self.safe_get(data, ['ip'])
        matched_at = self.safe_get(data, ['matched-at']) or host
        
        # Extract endpoint from matched-at URL
        endpoint = self.extract_endpoint_from_url(matched_at)
        
        # Determine protocol and port
        protocol = 'http'
        port = '80'
        if matched_at.startswith('https://'):
            protocol = 'https'
            port = '443'
        elif ':' in host and not host.startswith('['):  # Handle IPv6
            host_parts = host.split(':')
            if len(host_parts) > 1:
                host = host_parts[0]
                port = host_parts[1]
        
        return {
            'type': 'nuclei',
            'host': host,
            'endpoint': endpoint,
            'full_url': matched_at,
            'protocol': protocol,
            'port': port,
            'template_id': self.safe_get(data, ['template-id']),
            'name': self.safe_get(data, ['info', 'name']),
            'severity': self.safe_get(data, ['info', 'severity'], 'info').lower(),
            'description': self.safe_get(data, ['info', 'description']),
            'matched_at': matched_at,
            'title': self.safe_get(data, ['info', 'name']) or self.safe_get(data, ['template-id'])
        }
    
    def parse_nmap_scans(self, nmap_files):
        """Parse Nmap XML files"""
        if not nmap_files:
            return {}
        
        all_hosts = []
        total_open_ports = 0
        
        for nmap_file in nmap_files:
            print(f"🔍 Processing Nmap file: {os.path.basename(nmap_file)}")
            
            if not os.path.exists(nmap_file):
                print("  ❌ File not found")
                continue
                
            try:
                tree = ET.parse(nmap_file)
                root = tree.getroot()
                
                file_hosts = []
                for host in root.findall('host'):
                    host_info = {
                        'addresses': [],
                        'hostnames': [],
                        'open_ports': [],
                        'os_info': 'Unknown',
                        'endpoints': []  # Track web endpoints
                    }
                    
                    # Get IP addresses
                    for address in host.findall('address'):
                        if address.get('addrtype') == 'ipv4':
                            host_info['addresses'].append(address.get('addr'))
                    
                    # Get open ports and identify web endpoints
                    open_ports_count = 0
                    for port in host.findall('ports/port'):
                        state = port.find('state')
                        if state is not None and state.get('state') == 'open':
                            open_ports_count += 1
                            service_elem = port.find('service')
                            port_info = {
                                'port': port.get('portid'),
                                'protocol': port.get('protocol'),
                                'service': service_elem.get('name') if service_elem is not None else 'unknown',
                                'product': service_elem.get('product', ''),
                                'version': service_elem.get('version', '')
                            }
                            host_info['open_ports'].append(port_info)
                            
                            # Identify web service endpoints
                            service_name = port_info['service'].lower()
                            if service_name in ['http', 'https', 'http-proxy', 'http-alt']:
                                protocol = 'https' if port_info['port'] in ['443', '8443'] else 'http'
                                base_url = f"{protocol}://{host_info['addresses'][0]}:{port_info['port']}"
                                host_info['endpoints'].append({
                                    'url': base_url,
                                    'protocol': protocol,
                                    'port': port_info['port'],
                                    'service': port_info['service'],
                                    'base_path': '/'
                                })
                    
                    total_open_ports += open_ports_count
                    
                    if host_info['addresses']:
                        file_hosts.append(host_info)
                
                all_hosts.extend(file_hosts)
                print(f"  ✅ Found {len(file_hosts)} hosts with {open_ports_count} open ports")
                        
            except Exception as e:
                print(f"  ❌ Error parsing file: {e}")
        
        return {
            'hosts': all_hosts,
            'total_hosts': len(all_hosts),
            'total_open_ports': total_open_ports
        }
    
    def parse_vulnerability_scans(self, vuln_files):
        """Parse Nmap vulnerability scan files"""
        if not vuln_files:
            return []
        
        all_vulnerabilities = []
        
        for vuln_file in vuln_files:
            print(f"🛡️ Processing Vuln file: {os.path.basename(vuln_file)}")
            
            if not os.path.exists(vuln_file):
                print("  ❌ File not found")
                continue
                
            try:
                tree = ET.parse(vuln_file)
                root = tree.getroot()
                
                file_vulnerabilities = []
                for host in root.findall('host'):
                    host_ip = "Unknown"
                    address_elem = host.find('address')
                    if address_elem is not None:
                        host_ip = address_elem.get('addr', 'Unknown')
                    
                    for port in host.findall('ports/port'):
                        for script in port.findall('script'):
                            # Create endpoint for web services
                            endpoint = '/'
                            service_elem = port.find('service')
                            service_name = service_elem.get('name', '').lower() if service_elem else ''
                            
                            if service_name in ['http', 'https']:
                                protocol = 'https' if port.get('portid') in ['443', '8443'] else 'http'
                                endpoint = f"{protocol}://{host_ip}:{port.get('portid')}/"
                            
                            vuln_info = {
                                'type': 'nmap_vuln',
                                'host': host_ip,
                                'endpoint': endpoint,
                                'port': port.get('portid'),
                                'protocol': port.get('protocol'),
                                'script_id': script.get('id', 'unknown'),
                                'output': script.get('output', ''),
                                'severity': self.categorize_nmap_vuln(script.get('id', ''), script.get('output', '')),
                                'title': f"Nmap: {script.get('id', 'unknown')}"
                            }
                            file_vulnerabilities.append(vuln_info)
                
                all_vulnerabilities.extend(file_vulnerabilities)
                print(f"  ✅ Found {len(file_vulnerabilities)} vulnerabilities")
                            
            except Exception as e:
                print(f"  ❌ Error parsing file: {e}")
        
        return all_vulnerabilities
    
    def categorize_nmap_vuln(self, script_id, output):
        """Categorize Nmap vulnerability severity"""
        script_id = script_id.lower()
        output = output.lower()
        
        critical_keywords = ['shellshock', 'heartbleed', 'eternalblue', 'bluekeep']
        high_keywords = ['vuln', 'exploit', 'rce', 'sqli', 'xss', 'injection']
        medium_keywords = ['weak', 'default', 'info-disclosure', 'enum']
        
        if any(keyword in script_id or keyword in output for keyword in critical_keywords):
            return 'critical'
        elif any(keyword in script_id or keyword in output for keyword in high_keywords):
            return 'high'
        elif any(keyword in script_id or keyword in output for keyword in medium_keywords):
            return 'medium'
        else:
            return 'info'
    
    def generate_severity_stats(self, vulnerabilities):
        """Generate severity statistics from vulnerabilities"""
        stats = {
            'critical': 0, 'high': 0, 'medium': 0, 
            'low': 0, 'info': 0, 'unknown': 0,
            'total': len(vulnerabilities)
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown').lower()
            if severity in stats:
                stats[severity] += 1
        
        return stats
    
    def extract_all_endpoints(self, nmap_data, vulnerabilities):
        """Extract and organize all endpoints from scan data"""
        endpoints = {}
        
        # Extract from Nmap hosts
        for host in nmap_data.get('hosts', []):
            for endpoint_info in host.get('endpoints', []):
                base_url = endpoint_info['url']
                if base_url not in endpoints:
                    endpoints[base_url] = {
                        'url': base_url,
                        'protocol': endpoint_info['protocol'],
                        'port': endpoint_info['port'],
                        'vulnerabilities': [],
                        'host': host['addresses'][0] if host['addresses'] else 'Unknown'
                    }
        
        # Extract from vulnerabilities
        for vuln in vulnerabilities:
            if vuln.get('endpoint') and vuln['endpoint'] != '/':
                if vuln['type'] == 'nuclei':
                    # For Nuclei, use the full URL or construct from host/endpoint
                    base_url = f"{vuln.get('protocol', 'http')}://{vuln['host']}:{vuln.get('port', '80')}"
                    endpoint_path = vuln['endpoint']
                else:
                    # For Nmap vulns
                    base_url = vuln['endpoint'] if vuln['endpoint'].startswith('http') else f"http://{vuln['host']}:{vuln.get('port', '80')}"
                    endpoint_path = '/'
                
                if base_url not in endpoints:
                    endpoints[base_url] = {
                        'url': base_url,
                        'protocol': vuln.get('protocol', 'http'),
                        'port': vuln.get('port', '80'),
                        'vulnerabilities': [],
                        'host': vuln['host']
                    }
                
                # Add vulnerability to endpoint
                endpoints[base_url]['vulnerabilities'].append({
                    'type': vuln['type'],
                    'severity': vuln['severity'],
                    'title': vuln['title'],
                    'endpoint_path': vuln.get('endpoint', '/') if vuln['type'] == 'nuclei' else '/'
                })
        
        return list(endpoints.values())
    
    def create_comprehensive_report(self, doc, args, nmap_data, all_vulnerabilities, combined_stats):
        """Create comprehensive DOCX report with endpoint details"""
        # Title page
        title = doc.add_heading(args.title, 0)
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        doc.add_paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}")
        
        # Input files summary
        input_para = doc.add_paragraph("Input files: ")
        if args.nmap:
            input_para.add_run(f"Nmap ({len(args.nmap)}), ")
        if args.vuln:
            input_para.add_run(f"Vulnerability ({len(args.vuln)}), ")
        if args.nuclei:
            input_para.add_run(f"Nuclei ({len(args.nuclei)})")
        
        doc.add_page_break()
        
        # Executive Summary
        doc.add_heading('Executive Summary', 1)
        
        # Risk Overview
        risk_para = doc.add_paragraph()
        risk_para.add_run('Overall Risk Assessment:\n').bold = True
        
        critical_high = combined_stats.get('critical', 0) + combined_stats.get('high', 0)
        if critical_high > 0:
            risk_para.add_run(f'🚨 HIGH RISK - {critical_high} critical/high vulnerabilities found\n')
        elif combined_stats.get('medium', 0) > 0:
            risk_para.add_run(f'⚠️ MEDIUM RISK - {combined_stats.get("medium", 0)} medium vulnerabilities found\n')
        else:
            risk_para.add_run('✅ LOW RISK - No critical or high severity vulnerabilities found\n')
        
        # Statistics table
        stats_table = doc.add_table(rows=6, cols=2)
        stats_table.style = 'Light Grid Accent 1'
        
        stats_data = [
            ('Hosts Scanned', str(nmap_data.get('total_hosts', 0))),
            ('Open Ports', str(nmap_data.get('total_open_ports', 0))),
            ('Total Vulnerabilities', str(combined_stats.get('total', 0))),
            ('Critical Findings', str(combined_stats.get('critical', 0))),
            ('High Findings', str(combined_stats.get('high', 0))),
            ('Medium Findings', str(combined_stats.get('medium', 0)))
        ]
        
        for i, (label, value) in enumerate(stats_data):
            stats_table.cell(i, 0).text = label
            stats_table.cell(i, 1).text = value
        
        doc.add_paragraph()
        
        # Vulnerability Breakdown by Source
        doc.add_heading('Vulnerability Breakdown', 2)
        
        # Separate vulnerabilities by source
        nmap_vulns = [v for v in all_vulnerabilities if v['type'] == 'nmap_vuln']
        nuclei_vulns = [v for v in all_vulnerabilities if v['type'] == 'nuclei']
        
        source_table = doc.add_table(rows=3, cols=4)
        source_table.style = 'Light Grid Accent 2'
        
        # Header
        header_cells = source_table.rows[0].cells
        header_cells[0].text = 'Source'
        header_cells[1].text = 'Total'
        header_cells[2].text = 'Critical/High'
        header_cells[3].text = 'Medium/Low'
        
        # Nmap row
        nmap_cells = source_table.rows[1].cells
        nmap_cells[0].text = 'Nmap Scans'
        nmap_cells[1].text = str(len(nmap_vulns))
        nmap_high = len([v for v in nmap_vulns if v['severity'] in ['critical', 'high']])
        nmap_med_low = len([v for v in nmap_vulns if v['severity'] in ['medium', 'low']])
        nmap_cells[2].text = str(nmap_high)
        nmap_cells[3].text = str(nmap_med_low)
        
        # Nuclei row
        nuclei_cells = source_table.rows[2].cells
        nuclei_cells[0].text = 'Nuclei Scans'
        nuclei_cells[1].text = str(len(nuclei_vulns))
        nuclei_high = len([v for v in nuclei_vulns if v['severity'] in ['critical', 'high']])
        nuclei_med_low = len([v for v in nuclei_vulns if v['severity'] in ['medium', 'low']])
        nuclei_cells[2].text = str(nuclei_high)
        nuclei_cells[3].text = str(nuclei_med_low)
        
        doc.add_page_break()
        
        # Endpoint Inventory Section
        doc.add_heading('Discovered Endpoints', 1)
        doc.add_paragraph('This section lists all discovered endpoints and their associated vulnerabilities.')
        
        endpoints = self.extract_all_endpoints(nmap_data, all_vulnerabilities)
        
        if endpoints:
            for endpoint in endpoints:
                doc.add_heading(f"Endpoint: {endpoint['url']}", 2)
                
                # Endpoint details
                details_para = doc.add_paragraph()
                details_para.add_run('Protocol: ').bold = True
                details_para.add_run(f"{endpoint['protocol'].upper()}\n")
                details_para.add_run('Port: ').bold = True
                details_para.add_run(f"{endpoint['port']}\n")
                details_para.add_run('Host: ').bold = True
                details_para.add_run(f"{endpoint['host']}\n")
                
                # Vulnerabilities for this endpoint
                if endpoint['vulnerabilities']:
                    doc.add_heading('Vulnerabilities Found', 3)
                    
                    vuln_table = doc.add_table(rows=1, cols=4)
                    vuln_table.style = 'Light List Accent 1'
                    
                    # Header
                    vuln_header = vuln_table.rows[0].cells
                    vuln_header[0].text = 'Severity'
                    vuln_header[1].text = 'Type'
                    vuln_header[2].text = 'Title'
                    vuln_header[3].text = 'Path'
                    
                    for vuln in endpoint['vulnerabilities']:
                        row_cells = vuln_table.add_row().cells
                        
                        # Severity with color
                        severity_cell = row_cells[0].paragraphs[0]
                        severity_run = severity_cell.add_run(vuln['severity'].upper())
                        severity_run.font.color.rgb = self.severity_colors.get(vuln['severity'], self.severity_colors['unknown'])
                        severity_run.bold = True
                        
                        row_cells[1].text = vuln['type'].upper()
                        row_cells[2].text = vuln['title']
                        row_cells[3].text = vuln.get('endpoint_path', '/')
                
                doc.add_paragraph()
        else:
            doc.add_paragraph('No web endpoints discovered.')
        
        doc.add_page_break()
        
        # Detailed Vulnerability Findings
        if all_vulnerabilities:
            doc.add_heading('Detailed Vulnerability Findings', 1)
            
            # Group by severity
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                severity_vulns = [v for v in all_vulnerabilities if v['severity'] == severity]
                if severity_vulns:
                    doc.add_heading(f'{severity.upper()} Severity Findings', 2)
                    
                    for i, vuln in enumerate(severity_vulns, 1):
                        doc.add_heading(f'{i}. {vuln["title"]}', level=3)
                        
                        # Severity badge
                        severity_para = doc.add_paragraph()
                        severity_run = severity_para.add_run(f'SEVERITY: {severity.upper()} | TYPE: {vuln["type"].upper()}')
                        severity_run.bold = True
                        severity_run.font.color.rgb = self.severity_colors.get(severity)
                        
                        # Details table
                        details_table = doc.add_table(rows=0, cols=2)
                        details_table.style = 'Light Grid Accent 2'
                        
                        def add_row(label, value):
                            if value and str(value) != "N/A":
                                row_cells = details_table.add_row().cells
                                row_cells[0].text = str(label)
                                row_cells[1].text = str(value)
                        
                        add_row('Host', vuln.get('host'))
                        add_row('Endpoint', vuln.get('endpoint', 'N/A'))
                        if vuln.get('port'):
                            add_row('Port', f"{vuln.get('port')}/{vuln.get('protocol', 'tcp')}")
                        if vuln.get('template_id'):
                            add_row('Template ID', vuln.get('template_id'))
                        if vuln.get('description'):
                            add_row('Description', vuln.get('description'))
                        if vuln.get('output'):
                            add_row('Details', vuln.get('output'))
                        
                        doc.add_paragraph()
        
        # Recommendations
        doc.add_page_break()
        doc.add_heading('Security Recommendations', 1)
        
        recommendations = []
        
        # Critical/High vulnerabilities
        critical_high_count = combined_stats.get('critical', 0) + combined_stats.get('high', 0)
        if critical_high_count > 0:
            recommendations.append(f"🚨 IMMEDIATE ACTION: Address {critical_high_count} critical/high severity vulnerabilities")
        
        # Endpoint-specific recommendations
        if endpoints:
            recommendations.append(f"🌐 WEB ENDPOINTS: Review and secure {len(endpoints)} discovered endpoints")
            recommendations.append("🛡️ ENDPOINT PROTECTION: Implement WAF and input validation for all web endpoints")
        
        # Service-specific recommendations
        if any('http' in vuln.get('service', '').lower() or vuln.get('port') in ['80', '443', '8080', '8443'] 
               for host in nmap_data.get('hosts', []) for vuln in host.get('open_ports', [])):
            recommendations.append("🌐 WEB SERVICES: Implement WAF, update web applications, and configure security headers")
        
        if any(vuln.get('port') in ['22', '21', '23'] for host in nmap_data.get('hosts', []) for vuln in host.get('open_ports', [])):
            recommendations.append("🔐 REMOTE ACCESS: Harden SSH/FTP/Telnet configurations and use key-based authentication")
        
        # General recommendations
        recommendations.extend([
            "🛡️ NETWORK SECURITY: Implement network segmentation and firewall rules",
            "📊 MONITORING: Deploy SIEM and intrusion detection systems",
            "🔄 PATCHING: Establish regular patch management process",
            "📝 ACCESS CONTROL: Implement principle of least privilege",
            "🔍 TESTING: Conduct regular security assessments and penetration tests"
        ])
        
        for recommendation in recommendations:
            doc.add_paragraph(recommendation, style='List Bullet')
    
    def generate_summary_report(self, args):
        """Generate comprehensive summary report"""
        print("🚀 GENERATING SECURITY SCAN SUMMARY REPORT WITH ENDPOINTS")
        print("=" * 60)
        
        # Parse all data sources
        nmap_data = self.parse_nmap_scans(args.nmap or [])
        nmap_vulns = self.parse_vulnerability_scans(args.vuln or [])
        nuclei_vulns = self.parse_nuclei_scans(args.nuclei or [])
        
        # Combine all vulnerabilities
        all_vulnerabilities = nmap_vulns + nuclei_vulns
        
        # Generate statistics
        nmap_stats = self.generate_severity_stats(nmap_vulns)
        nuclei_stats = self.generate_severity_stats(nuclei_vulns)
        combined_stats = self.generate_severity_stats(all_vulnerabilities)
        
        # Extract endpoints
        endpoints = self.extract_all_endpoints(nmap_data, all_vulnerabilities)
        
        # Print final summary
        print("\n" + "=" * 60)
        print("📊 COMPREHENSIVE SECURITY SUMMARY")
        print("=" * 60)
        print(f"🎯 TARGETS")
        print(f"   Hosts Scanned: {nmap_data.get('total_hosts', 0)}")
        print(f"   Open Ports: {nmap_data.get('total_open_ports', 0)}")
        print(f"   Discovered Endpoints: {len(endpoints)}")
        
        print(f"\n🔍 VULNERABILITY OVERVIEW")
        print(f"   Total Findings: {combined_stats.get('total', 0)}")
        print(f"   Critical: {combined_stats.get('critical', 0)}")
        print(f"   High: {combined_stats.get('high', 0)}")
        print(f"   Medium: {combined_stats.get('medium', 0)}")
        print(f"   Low: {combined_stats.get('low', 0)}")
        print(f"   Informational: {combined_stats.get('info', 0)}")
        
        print(f"\n📋 BREAKDOWN BY SCAN TYPE")
        print(f"   Nmap Vulnerabilities: {nmap_stats.get('total', 0)}")
        print(f"   Nuclei Vulnerabilities: {nuclei_stats.get('total', 0)}")
        
        # Endpoint summary
        if endpoints:
            print(f"\n🌐 DISCOVERED ENDPOINTS")
            for endpoint in endpoints:
                vuln_count = len(endpoint['vulnerabilities'])
                print(f"   {endpoint['url']} ({vuln_count} vulnerabilities)")
        
        # Risk assessment
        critical_high = combined_stats.get('critical', 0) + combined_stats.get('high', 0)
        if critical_high > 0:
            print(f"\n🚨 RISK LEVEL: HIGH")
            print(f"   {critical_high} critical/high severity vulnerabilities require immediate attention")
        elif combined_stats.get('medium', 0) > 0:
            print(f"\n⚠️ RISK LEVEL: MEDIUM")
            print(f"   {combined_stats.get('medium', 0)} medium severity vulnerabilities should be addressed")
        else:
            print(f"\n✅ RISK LEVEL: LOW")
            print(f"   No critical or high severity vulnerabilities detected")
        
        print("=" * 60)
        
        # Create DOCX report
        doc = Document()
        self.create_comprehensive_report(doc, args, nmap_data, all_vulnerabilities, combined_stats)
        doc.save(args.output)
        print(f"\n💾 Detailed report with endpoints saved to: {args.output}")

def main():
    reporter = EndpointSecuritySummaryReporter()
    args = reporter.parse_arguments()
    reporter.generate_summary_report(args)

if __name__ == "__main__":
    main()
