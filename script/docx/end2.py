#!/usr/bin/env python3
"""
Enhanced Security Summary Reporter with Endpoint Details (Nmap, Nuclei, Nettacker)
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
            'critical': RGBColor(178, 34, 34),     # Firebrick red
            'high': RGBColor(255, 0, 0),           # Red
            'medium': RGBColor(255, 140, 0),       # Dark orange
            'low': RGBColor(255, 215, 0),          # Gold
            'info': RGBColor(100, 149, 237),       # Cornflower blue
            'unknown': RGBColor(128, 128, 128)     # Gray
        }
    
    def parse_arguments(self):
        parser = argparse.ArgumentParser(
            description='Security Scan Summary Report with Endpoint Details',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog='''
Examples:
  # Full comprehensive report with endpoints
  python security_summary.py -n nmap.xml -v vuln.xml -j nuclei.json -k nettacker.json -o report.docx
  
  # Web-focused report (Nuclei and Nettacker)
  python security_summary.py -j nuclei.json -k nettacker.json -o web_report.docx
            '''
        )
        
        parser.add_argument('-n', '--nmap', nargs='+', help='Nmap XML file(s)')
        parser.add_argument('-v', '--vuln', nargs='+', help='Nmap vulnerability XML file(s)')
        parser.add_argument('-j', '--nuclei', nargs='+', help='Nuclei JSON file(s)')
        # --- NETTACKER ADDITION ---
        parser.add_argument('-k', '--nettacker', nargs='+', help='Nettacker JSON file(s)')
        # --------------------------
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

    # --- NETTACKER PARSING FUNCTION ADDITION ---
    def parse_nettacker_scans(self, nettacker_files):
        """Parse Nettacker JSON files"""
        if not nettacker_files:
            return []

        all_vulnerabilities = []

        for nettacker_file in nettacker_files:
            print(f"🔗 Processing Nettacker file: {os.path.basename(nettacker_file)}")

            if not os.path.exists(nettacker_file):
                print(f"  ❌ File not found")
                continue

            try:
                with open(nettacker_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                if isinstance(data, list):
                    file_vulnerabilities = []
                    for item in data:
                        if self.is_valid_nettacker_finding(item):
                            vuln_info = self.create_nettacker_vuln_info(item)
                            file_vulnerabilities.append(vuln_info)
                    
                    all_vulnerabilities.extend(file_vulnerabilities)
                    print(f"  ✅ Added {len(file_vulnerabilities)} vulnerabilities")
                else:
                    print("  ❌ JSON structure is not a list (expected Nettacker output)")

            except json.JSONDecodeError:
                print("  ❌ Error decoding JSON")
            except Exception as e:
                print(f"  ❌ Error reading file: {e}")
        
        print(f"🎯 Total Nettacker vulnerabilities: {len(all_vulnerabilities)}")
        return all_vulnerabilities

    def is_valid_nettacker_finding(self, data):
        """Check if Nettacker finding is valid"""
        return isinstance(data, dict) and 'target' in data and 'event_data' in data
    
    def normalize_nettacker_severity(self, severity_str):
        """Map Nettacker severity to standard levels"""
        severity_str = str(severity_str).lower()
        if 'critical' in severity_str:
            return 'critical'
        elif 'high' in severity_str:
            return 'high'
        elif 'medium' in severity_str:
            return 'medium'
        elif 'low' in severity_str:
            return 'low'
        else:
            return 'info'

    def create_nettacker_vuln_info(self, data):
        """Create standardized vulnerability info from Nettacker data"""
        target = self.safe_get(data, ['target'], 'Unknown')
        port = self.safe_get(data, ['port'], 'N/A')
        
        # Nettacker target might be "http://host:port/"
        try:
            parsed_target = urlparse(target)
            host = parsed_target.netloc.split(':')[0] if parsed_target.netloc else target
            if not host:
                host = target
            
            # Determine base URL for the endpoint
            if parsed_target.scheme in ['http', 'https']:
                protocol = parsed_target.scheme
                port = str(parsed_target.port) if parsed_target.port else ('443' if protocol == 'https' else '80')
                base_url = f"{protocol}://{host}:{port}"
                endpoint = parsed_target.path if parsed_target.path else '/'
            else:
                protocol = self.safe_get(data, ['protocol'], 'tcp')
                base_url = f"{host}:{port}"
                endpoint = '/'
        except Exception:
            host = target
            protocol = self.safe_get(data, ['protocol'], 'tcp')
            base_url = f"{host}:{port}"
            endpoint = '/'

        event_data = self.safe_get(data, ['event_data'], {})
        module_name = self.safe_get(data, ['module_name'], 'Nettacker Scan')
        
        title = self.safe_get(event_data, ['response'], module_name).split('\n')[0].strip()
        description = self.safe_get(event_data, ['response'], 'N/A')
        severity = self.normalize_nettacker_severity(self.safe_get(data, ['severity'], 'info'))

        return {
            'type': 'nettacker',
            'host': host,
            'endpoint': endpoint,
            'full_url': base_url + endpoint,
            'protocol': protocol,
            'port': port,
            'template_id': self.safe_get(data, ['id']),
            'name': title,
            'severity': severity,
            'description': description,
            'matched_at': self.safe_get(data, ['target']),
            'title': title
        }
    # ---------------------------------------------
    
    # [Rest of the existing parsing functions for Nuclei, Nmap, and Nmap Vuln remain here]
    # (Leaving them out of this response for brevity, but they are in the full script.)
    
    def parse_nuclei_scans(self, nuclei_files):
        # ... (Existing Nuclei parsing logic)
        pass # Placeholder
    
    def is_valid_nuclei_finding(self, data):
        # ... (Existing Nuclei validation logic)
        pass # Placeholder
    
    def create_nuclei_vuln_info(self, data):
        # ... (Existing Nuclei info creation logic)
        pass # Placeholder

    def parse_nmap_scans(self, nmap_files):
        # ... (Existing Nmap parsing logic)
        pass # Placeholder
    
    def parse_vulnerability_scans(self, vuln_files):
        # ... (Existing Nmap Vuln parsing logic)
        pass # Placeholder

    def categorize_nmap_vuln(self, script_id, output):
        # ... (Existing Nmap severity categorization logic)
        pass # Placeholder

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
                # Standardize endpoint base URL based on host/port/protocol
                protocol = vuln.get('protocol', 'http')
                port = vuln.get('port', '80')
                host = vuln['host']
                endpoint_path = vuln['endpoint']
                
                # Use full URL if provided and looks like a URL (e.g., from Nuclei/Nettacker)
                if vuln.get('full_url', '').startswith('http'):
                    try:
                        parsed_url = urlparse(vuln['full_url'])
                        # Use scheme, host, and port for the base_url
                        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                        endpoint_path = parsed_url.path
                        if parsed_url.query:
                            endpoint_path += '?' + parsed_url.query
                        # Check if it was a root-level finding to avoid duplicating the base URL in 'path'
                        if endpoint_path == '/':
                            endpoint_path = vuln['endpoint'] if vuln.get('type') == 'nettacker' and vuln['endpoint'] != '/' else '/'

                    except:
                        base_url = f"{protocol}://{host}:{port}"
                else:
                    base_url = f"{protocol}://{host}:{port}"
                
                # Ensure path component is included for Nuclei/Nettacker where applicable
                if vuln['type'] in ['nuclei', 'nettacker'] and vuln.get('endpoint') not in ['/', base_url]:
                    pass # We'll use the full_url or path in the table below

                if base_url not in endpoints:
                    endpoints[base_url] = {
                        'url': base_url,
                        'protocol': protocol,
                        'port': port,
                        'vulnerabilities': [],
                        'host': host
                    }
                
                # Add vulnerability to endpoint
                endpoints[base_url]['vulnerabilities'].append({
                    'type': vuln['type'],
                    'severity': vuln['severity'],
                    'title': vuln['title'],
                    'endpoint_path': endpoint_path if vuln['type'] == 'nuclei' or vuln['type'] == 'nettacker' else '/'
                })
        
        return list(endpoints.values())

    # [The docx generation functions create_comprehensive_report, etc. remain the same]

    def create_comprehensive_report(self, doc, args, nmap_data, all_vulnerabilities, combined_stats):
        # ... (Existing docx generation logic, which is extensive, remains the same)
        # Note: The 'Type' column in the Vulnerabilities Found table and 'Type' in Detailed Findings will now correctly display 'NETTACKER'.
        pass # Placeholder

    def generate_summary_report(self, args):
        """Generate comprehensive summary report"""
        print("🚀 GENERATING SECURITY SCAN SUMMARY REPORT WITH ENDPOINTS")
        print("=" * 60)
        
        # Parse all data sources
        nmap_data = self.parse_nmap_scans(args.nmap or [])
        nmap_vulns = self.parse_vulnerability_scans(args.vuln or [])
        nuclei_vulns = self.parse_nuclei_scans(args.nuclei or [])
        # --- NETTACKER INTEGRATION ---
        nettacker_vulns = self.parse_nettacker_scans(args.nettacker or [])
        
        # Combine all vulnerabilities
        all_vulnerabilities = nmap_vulns + nuclei_vulns + nettacker_vulns
        # -----------------------------
        
        # Generate statistics
        nmap_stats = self.generate_severity_stats(nmap_vulns)
        nuclei_stats = self.generate_severity_stats(nuclei_vulns)
        nettacker_stats = self.generate_severity_stats(nettacker_vulns) # New stats
        combined_stats = self.generate_severity_stats(all_vulnerabilities)
        
        # Extract endpoints
        endpoints = self.extract_all_endpoints(nmap_data, all_vulnerabilities)
        
        # Print final summary (Updated to include Nettacker)
        print("\n" + "=" * 60)
        print("📊 COMPREHENSIVE SECURITY SUMMARY")
        print("=" * 60)
        print(f"🎯 TARGETS")
        print(f"    Hosts Scanned: {nmap_data.get('total_hosts', 0)}")
        print(f"    Open Ports: {nmap_data.get('total_open_ports', 0)}")
        print(f"    Discovered Endpoints: {len(endpoints)}")
        
        print(f"\n🔍 VULNERABILITY OVERVIEW")
        print(f"    Total Findings: {combined_stats.get('total', 0)}")
        print(f"    Critical: {combined_stats.get('critical', 0)}")
        print(f"    High: {combined_stats.get('high', 0)}")
        print(f"    Medium: {combined_stats.get('medium', 0)}")
        print(f"    Low: {combined_stats.get('low', 0)}")
        print(f"    Informational: {combined_stats.get('info', 0)}")
        
        print(f"\n📋 BREAKDOWN BY SCAN TYPE")
        print(f"    Nmap Vulnerabilities: {nmap_stats.get('total', 0)}")
        print(f"    Nuclei Vulnerabilities: {nuclei_stats.get('total', 0)}")
        print(f"    Nettacker Vulnerabilities: {nettacker_stats.get('total', 0)}") # New line
        
        # Endpoint summary
        if endpoints:
            print(f"\n🌐 DISCOVERED ENDPOINTS")
            for endpoint in endpoints:
                vuln_count = len(endpoint['vulnerabilities'])
                print(f"    {endpoint['url']} ({vuln_count} vulnerabilities)")
        
        # Risk assessment
        critical_high = combined_stats.get('critical', 0) + combined_stats.get('high', 0)
        if critical_high > 0:
            print(f"\n🚨 RISK LEVEL: HIGH")
            print(f"    {critical_high} critical/high severity vulnerabilities require immediate attention")
        elif combined_stats.get('medium', 0) > 0:
            print(f"\n⚠️ RISK LEVEL: MEDIUM")
            print(f"    {combined_stats.get('medium', 0)} medium severity vulnerabilities should be addressed")
        else:
            print(f"\n✅ RISK LEVEL: LOW")
            print(f"    No critical or high severity vulnerabilities detected")
        
        print("=" * 60)
        
        # Create DOCX report
        doc = Document()
        # You will need to re-include the full create_comprehensive_report function from your original script here, 
        # as it references combined_stats and all_vulnerabilities which now include Nettacker data.
        # Make sure you also update the 'Vulnerability Breakdown' table in create_comprehensive_report 
        # to include a row for Nettacker vulnerabilities.
        self.create_comprehensive_report(doc, args, nmap_data, all_vulnerabilities, combined_stats)
        doc.save(args.output)
        print(f"\n💾 Detailed report with endpoints saved to: {args.output}")

# The main function logic remains the same
# def main():
#     reporter = EndpointSecuritySummaryReporter()
#     args = reporter.parse_arguments()
#     reporter.generate_summary_report(args)

# if __name__ == "__main__":
#     main()
