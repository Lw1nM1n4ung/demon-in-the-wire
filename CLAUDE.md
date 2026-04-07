# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Wire_Ghost is a security scanning orchestration toolkit that coordinates multiple security tools (Nmap, Nuclei, Dirsearch, Nettacker) into a parallel pipeline, then generates DOCX/XLSX reports from the results.

## Running the Tool

```bash
# Full scanning pipeline against a target network
./script/main.sh 192.168.1.0/24
```

This discovers live hosts, runs parallel port scans, detects web services, executes vulnerability scans, and generates reports. Output goes to `/root/output/<target_dir>/`.

## Python Environment

Python 3.12 virtual environment at `script/docx/env/`. Activate with:

```bash
source /home/demon/Tools/Wire_Ghost/script/docx/env/bin/activate
```

Key packages: `python-docx`, `openpyxl`, `requests`, `beautifulsoup4`, `lxml`.

## Running Individual Scripts

All Python scripts are in `script/docx/` and can be run standalone:

```bash
# Generate comprehensive security report (Nmap + Nuclei + vuln scans)
python3 script/docx/end.py -n <nmap.xml> -v <vuln.xml> -j <nuclei.json> -o report.docx

# Convert Nmap XML to DOCX
python3 script/docx/xml_to_docx.py <input.xml> <output_dir>

# Convert Nmap XML to Excel
python3 script/docx/xml_to_xlsx.py -i <input.xml> -o output.xlsx

# Extract port summary as text
python3 script/docx/sheet.py <nmap.xml>

# Discover web services from Nmap results
python3 script/docx/web_finder.py <nmap.xml> <output.txt>

# Generate vuln scan commands from Nmap XML
python3 script/docx/nmap_parser.py <nmap.xml>
```

## Architecture

```
main.sh (bash orchestration)
│
├── Phase 1: Live Host Discovery
│   nmap -sn + fping → live_host list
│
├── Phase 2: Per-IP Parallel Pipeline (xargs -P10)
│   ├── Nmap full port scan → XML
│   ├── xml_to_docx.py / sheet.py → per-host reports
│   ├── web_finder.py → URL list
│   ├── Nuclei scans → JSON
│   ├── Nmap --script=vuln → vuln XML
│   └── xml_to_xlsx.py → Excel summary
│
└── Phase 3: Final Reports
    └── end.py → consolidated endpoint DOCX per IP
```

**Orchestration layer** (`script/main.sh`): Bash script managing the full pipeline with `xargs` parallelism (10 concurrent scans default). Calls external tools and Python scripts in sequence per host.

**Parser/report layer** (`script/docx/*.py`): Python modules that parse tool output (Nmap XML, Nuclei JSON, Nettacker JSON) and generate DOCX/XLSX reports using `python-docx` and `openpyxl`.

## Output Directory Structure

```
/root/output/<target_dir>/
├── all/
│   ├── live_host/          # Discovered live IPs
│   ├── web/                # Aggregated web targets
│   └── nmap/command/       # Generated vuln scan commands
├── ip/<IP>/
│   ├── nmap/xml/           # Nmap scan results
│   ├── nmap/docx/          # Per-host DOCX reports
│   ├── web/nuclei/         # Nuclei findings
│   ├── web/dirsearch/      # Directory enumeration results
│   └── vuln/               # Vulnerability scan outputs
└── final_reports/
    ├── ports_xlsx/          # Excel port summaries
    └── summary_vuln_report/ # Consolidated DOCX reports
```

## Key Files

| File | Role |
|------|------|
| `script/main.sh` | Main orchestration script (entry point) |
| `script/docx/end.py` | Comprehensive report generator (primary, supports Nmap + Nuclei + Nettacker) |
| `script/docx/end2.py`, `end3.py` | Alternative report generator variants |
| `script/docx/xml_to_docx.py` | Nmap XML → DOCX converter |
| `script/docx/xml_to_xlsx.py` | Nmap XML → Excel converter |
| `script/docx/web_finder.py` | Web service discovery from Nmap results |
| `script/docx/nmap_parser.py` | Generates vuln scan commands from Nmap XML |
| `script/docx/nuclei.py` | Nuclei JSON → DOCX converter |
| `script/docx/port_vuln.py` | Port vulnerability reporter |
| `script/docx/sheet.py` | Port summary text formatter |

## Vulnerability Data Schema

All parsers normalize findings to a common structure used in report generation:

```python
{
    'type': 'nmap_vuln' | 'nuclei' | 'nettacker',
    'host': str,
    'endpoint': str,
    'port': str,
    'protocol': str,
    'severity': 'critical' | 'high' | 'medium' | 'low' | 'info',
    'title': str,
    'description': str
}
```

Severity levels map to consistent RGB colors across all report types via `severity_color()`.

## External Tool Dependencies

Requires these tools installed on the system: `nmap`, `nuclei`, `dirsearch`, `fping`, `httpx`, `nettacker`.

## Notes

- Hidden dot-prefixed scripts (`.nmap_live.sh`, `.nmap_live2.sh`, `.nmap_live_err.sh`) are legacy/alternative implementations
- `main.sh` hardcodes output to `/root/output/` and expects the Python venv at `/root/.script/docx/env/`
- No test suite, linting, or CI/CD configuration exists
- Not currently a git repository
