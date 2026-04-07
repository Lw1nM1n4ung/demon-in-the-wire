#!/usr/bin/env python3
"""
Nuclei Output to DOCX Converter - Fixed Version
Usage: python nuclei_to_docx.py -i results.json -o report.docx
"""

import argparse
import json
import sys
from pathlib import Path
from docx import Document
from docx.shared import RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from datetime import datetime
import re

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Convert Nuclei JSON output to DOCX format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Basic usage
  python nuclei_to_docx.py -i nuclei_results.json -o report.docx
  
  # With custom title and include requests/responses
  python nuclei_to_docx.py -i results.json -o scan_report.docx -t "Security Scan Report" --include-requests
  
  # Convert multiple files
  python nuclei_to_docx.py -i scan1.json scan2.json -o combined_report.docx
  
  # Minimal output
  python nuclei_to_docx.py -i results.json -o quick_report.docx --minimal
        '''
    )
    
    parser.add_argument('-i', '--input', 
                       nargs='+', 
                       required=True,
                       help='Input JSON file(s) from Nuclei')
    
    parser.add_argument('-o', '--output', 
                       required=True,
                       help='Output DOCX file path')
    
    parser.add_argument('-t', '--title',
                       default='Nuclei Vulnerability Report',
                       help='Report title (default: "Nuclei Vulnerability Report")')
    
    parser.add_argument('--minimal',
                       action='store_true',
                       help='Generate minimal report without detailed information')
    
    parser.add_argument('--include-requests',
                       action='store_true',
                       help='Include HTTP requests and responses in report')
    
    parser.add_argument('--severity',
                       nargs='+',
                       choices=['critical', 'high', 'medium', 'low', 'info'],
                       help='Filter by severity levels')
    
    parser.add_argument('--template-id',
                       nargs='+',
                       help='Filter by template IDs')
    
    parser.add_argument('--exclude',
                       nargs='+',
                       help='Exclude specific template IDs')
    
    return parser.parse_args()

def severity_color(severity):
    """Return RGB color for severity level"""
    colors = {
        'critical': RGBColor(139, 0, 0),      # Dark Red
        'high': RGBColor(255, 0, 0),          # Red
        'medium': RGBColor(255, 165, 0),      # Orange
        'low': RGBColor(255, 255, 0),         # Yellow
        'info': RGBColor(173, 216, 230),      # Light Blue
        'unknown': RGBColor(128, 128, 128)    # Gray
    }
    return colors.get(severity.lower(), colors['unknown'])

def safe_get(obj, keys, default="N/A"):
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

def is_valid_vulnerability(vuln):
    """Check if the vulnerability object is valid"""
    if not isinstance(vuln, dict):
        return False
    
    # Check for required fields
    if not vuln.get("template-id") and not vuln.get("info", {}).get("name"):
        return False
    
    return True

def normalize_vulnerability(vuln):
    """Normalize vulnerability data to handle different Nuclei output formats"""
    if not isinstance(vuln, dict):
        return None
    
    # Ensure nested structures exist
    if "info" not in vuln:
        vuln["info"] = {}
    
    # Normalize severity
    if "severity" in vuln and "severity" not in vuln["info"]:
        vuln["info"]["severity"] = vuln["severity"]
    
    # Ensure common fields
    vuln.setdefault("host", "Unknown")
    vuln.setdefault("matched-at", "Unknown")
    vuln.setdefault("template-id", "Unknown")
    
    vuln["info"].setdefault("name", "Unknown Template")
    vuln["info"].setdefault("severity", "unknown")
    vuln["info"].setdefault("description", "No description available")
    vuln["info"].setdefault("author", "Unknown")
    vuln["info"].setdefault("reference", [])
    vuln["info"].setdefault("tags", [])
    
    return vuln

def filter_vulnerabilities(vulnerabilities, args):
    """Filter vulnerabilities based on arguments"""
    filtered = []
    
    for vuln in vulnerabilities:
        if not is_valid_vulnerability(vuln):
            continue
            
        # Normalize the vulnerability data
        vuln = normalize_vulnerability(vuln)
        if not vuln:
            continue
        
        # Severity filter
        if args.severity:
            severity = safe_get(vuln, ["info", "severity"], "unknown").lower()
            if severity not in [s.lower() for s in args.severity]:
                continue
        
        # Template ID filter
        if args.template_id:
            template_id = safe_get(vuln, ["template-id"], "")
            if template_id not in args.template_id:
                continue
        
        # Exclude filter
        if args.exclude:
            template_id = safe_get(vuln, ["template-id"], "")
            if template_id in args.exclude:
                continue
        
        filtered.append(vuln)
    
    return filtered

def create_executive_summary(doc, vulnerabilities, args):
    """Create executive summary section"""
    doc.add_heading('Executive Summary', 1)
    
    # Severity distribution
    severity_count = {
        'critical': 0, 'high': 0, 'medium': 0, 
        'low': 0, 'info': 0, 'unknown': 0
    }
    
    template_count = {}
    
    for vuln in vulnerabilities:
        if not is_valid_vulnerability(vuln):
            continue
            
        severity = safe_get(vuln, ["info", "severity"], "unknown").lower()
        severity_count[severity] = severity_count.get(severity, 0) + 1
        
        template_id = safe_get(vuln, ["template-id"], "unknown")
        template_count[template_id] = template_count.get(template_id, 0) + 1
    
    # Summary paragraph
    summary_para = doc.add_paragraph()
    summary_para.add_run('Total Vulnerabilities: ').bold = True
    summary_para.add_run(f'{len(vulnerabilities)}\n')
    
    summary_para.add_run('Unique Templates: ').bold = True
    summary_para.add_run(f'{len(template_count)}\n')
    
    summary_para.add_run('Scan Date: ').bold = True
    summary_para.add_run(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n')
    
    # Severity table
    if not args.minimal:
        doc.add_heading('Severity Distribution', 2)
        table = doc.add_table(rows=1, cols=3)
        table.style = 'Light Grid Accent 1'
        
        # Header
        hdr_cells = table.rows[0].cells
        hdr_cells[0].text = 'Severity'
        hdr_cells[1].text = 'Count'
        hdr_cells[2].text = 'Percentage'
        
        for severity in ['critical', 'high', 'medium', 'low', 'info', 'unknown']:
            count = severity_count[severity]
            if count > 0:
                percentage = (count / len(vulnerabilities)) * 100
                row_cells = table.add_row().cells
                
                # Severity with color
                severity_cell = row_cells[0]
                severity_run = severity_cell.paragraphs[0].add_run(severity.upper())
                severity_run.font.color.rgb = severity_color(severity)
                severity_run.bold = True
                
                row_cells[1].text = str(count)
                row_cells[2].text = f'{percentage:.1f}%'

def create_detailed_findings(doc, vulnerabilities, args):
    """Create detailed findings section"""
    doc.add_heading('Detailed Findings', 1)
    
    for i, vuln in enumerate(vulnerabilities, 1):
        if not is_valid_vulnerability(vuln):
            print(f"Warning: Skipping invalid vulnerability at index {i}")
            continue
            
        severity = safe_get(vuln, ["info", "severity"], "unknown").lower()
        template_name = safe_get(vuln, ["info", "name"], "Unknown Template")
        
        # Vulnerability header
        header = doc.add_heading(f'{i}. {template_name}', level=2)
        
        # Severity badge
        severity_para = doc.add_paragraph()
        severity_run = severity_para.add_run(f'SEVERITY: {severity.upper()}')
        severity_run.bold = True
        severity_run.font.color.rgb = severity_color(severity)
        
        # Basic information table
        if not args.minimal:
            info_table = doc.add_table(rows=0, cols=2)
            info_table.style = 'Light Grid Accent 2'
            
            def add_row(table, label, value):
                if value and str(value).strip() and str(value) != "N/A":
                    row_cells = table.add_row().cells
                    row_cells[0].text = str(label)
                    row_cells[1].text = str(value)
            
            add_row(info_table, 'Template ID', safe_get(vuln, ["template-id"]))
            add_row(info_table, 'Host', safe_get(vuln, ["host"]))
            add_row(info_table, 'Matched At', safe_get(vuln, ["matched-at"]))
            add_row(info_table, 'Description', safe_get(vuln, ["info", "description"]))
            add_row(info_table, 'Author', safe_get(vuln, ["info", "author"]))
            
            tags = safe_get(vuln, ["info", "tags"], [])
            if tags and isinstance(tags, list):
                add_row(info_table, 'Tags', ', '.join(tags))
        
        # References
        references = safe_get(vuln, ["info", "reference"], [])
        if references and not args.minimal:
            ref_para = doc.add_paragraph()
            ref_para.add_run('References:\n').bold = True
            
            if isinstance(references, list):
                for ref in references:
                    if ref and str(ref).strip():
                        doc.add_paragraph(str(ref), style='List Bullet')
            elif isinstance(references, str) and references.strip():
                doc.add_paragraph(references, style='List Bullet')
        
        # HTTP Request/Response
        if args.include_requests and not args.minimal:
            http_request = vuln.get("request", "")
            http_response = vuln.get("response", "")
            
            if http_request:
                doc.add_heading('HTTP Request', level=3)
                # Truncate very long requests
                if len(str(http_request)) > 10000:
                    http_request = str(http_request)[:10000] + "\n\n[TRUNCATED - REQUEST TOO LONG]"
                req_para = doc.add_paragraph(str(http_request))
                req_para.style = 'Normal'
            
            if http_response:
                doc.add_heading('HTTP Response', level=3)
                # Truncate very long responses
                if len(str(http_response)) > 15000:
                    http_response = str(http_response)[:15000] + "\n\n[TRUNCATED - RESPONSE TOO LONG]"
                resp_para = doc.add_paragraph(str(http_response))
                resp_para.style = 'Normal'
        
        # Add spacing between vulnerabilities
        doc.add_paragraph()

def load_vulnerabilities(input_files):
    """Load vulnerabilities from input files with error handling"""
    all_vulnerabilities = []
    invalid_count = 0
    
    for input_file in input_files:
        if not Path(input_file).exists():
            print(f"Error: Input file not found: {input_file}")
            sys.exit(1)
            
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            
                            # Handle both list and dict formats
                            if isinstance(data, list):
                                for item in data:
                                    if is_valid_vulnerability(item):
                                        all_vulnerabilities.append(item)
                                    else:
                                        invalid_count += 1
                                        print(f"Warning: Invalid vulnerability in {input_file}:{line_num}")
                            elif isinstance(data, dict):
                                if is_valid_vulnerability(data):
                                    all_vulnerabilities.append(data)
                                else:
                                    invalid_count += 1
                                    print(f"Warning: Invalid vulnerability in {input_file}:{line_num}")
                            else:
                                invalid_count += 1
                                print(f"Warning: Unexpected data type in {input_file}:{line_num} - {type(data)}")
                                
                        except json.JSONDecodeError as e:
                            invalid_count += 1
                            print(f"Warning: JSON decode error in {input_file}:{line_num}: {e}")
                            
        except Exception as e:
            print(f"Error reading file {input_file}: {e}")
            sys.exit(1)
    
    if invalid_count > 0:
        print(f"Skipped {invalid_count} invalid entries")
    
    return all_vulnerabilities

def nuclei_to_docx(args):
    """Main conversion function"""
    try:
        # Initialize document
        doc = Document()
        
        # Set document properties
        doc.core_properties.title = args.title
        doc.core_properties.author = "Nuclei Scanner"
        doc.core_properties.comments = f"Generated from {len(args.input)} input file(s)"
        
        # Title page
        title = doc.add_heading(args.title, 0)
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        
        doc.add_paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}")
        doc.add_paragraph(f"Input files: {', '.join(args.input)}")
        doc.add_page_break()
        
        # Load vulnerabilities with robust error handling
        all_vulnerabilities = load_vulnerabilities(args.input)
        print(f"Loaded {len(all_vulnerabilities)} valid vulnerabilities from {len(args.input)} file(s)")
        
        if not all_vulnerabilities:
            doc.add_paragraph("No valid vulnerabilities found in the input files.")
            doc.save(args.output)
            print(f"Report saved to: {args.output} (no vulnerabilities)")
            return
        
        # Apply filters
        filtered_vulnerabilities = filter_vulnerabilities(all_vulnerabilities, args)
        print(f"After filtering: {len(filtered_vulnerabilities)} vulnerabilities")
        
        if not filtered_vulnerabilities:
            doc.add_paragraph("No vulnerabilities found matching the specified criteria.")
            doc.save(args.output)
            print(f"Report saved to: {args.output} (empty after filtering)")
            return
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}
        filtered_vulnerabilities.sort(key=lambda x: severity_order.get(
            safe_get(x, ["info", "severity"], "unknown").lower(), 5
        ))
        
        # Create report sections
        create_executive_summary(doc, filtered_vulnerabilities, args)
        doc.add_page_break()
        create_detailed_findings(doc, filtered_vulnerabilities, args)
        
        # Save document
        doc.save(args.output)
        print(f"Successfully converted to: {args.output}")
        print(f"Total vulnerabilities in report: {len(filtered_vulnerabilities)}")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

def main():
    args = parse_arguments()
    nuclei_to_docx(args)

if __name__ == "__main__":
    main()
