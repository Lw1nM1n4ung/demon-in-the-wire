# Architecture & Technical Documentation

Detailed technical reference for Demon in the Wire (wireghost) — automated security scanning orchestration toolkit.

---

## Table of Contents

- [Pipeline Flow](#pipeline-flow)
- [External Tools](#external-tools)
- [Scanner Fallback Chain](#scanner-fallback-chain)
- [Libraries & Dependencies](#libraries--dependencies)
- [Data Models](#data-models)
- [Parsers](#parsers)
- [Async Concurrency Model](#async-concurrency-model)
- [Configuration System](#configuration-system)
- [Report System](#report-system)
- [Output Directory Structure](#output-directory-structure)
- [Project File Map](#project-file-map)

---

## Pipeline Flow

The complete execution path from CLI entry to final reports:

```
wireghost scan 192.168.1.0/24
    │
    ▼
cli.py: scan()
    │  Parses CLI args, builds ScanConfig.load(target, **overrides)
    │  Calls asyncio.run(run_pipeline(config))
    │
    ▼
pipeline/orchestrator.py: run_pipeline(config)
    │
    ├── setup_logging(output_dir, verbose)          # utils/log.py
    ├── build_output_tree(output_dir, target_name)  # utils/fs.py
    │
    ├── Phase 1: Tool Check
    │   ├── check_tools(["nmap", "fping", ...])     # utils/process.py
    │   └── Log optional scanner availability (naabu, masscan)
    │
    ├── Phase 2: Host Discovery
    │   └── discovery.discover_hosts(config, tree)
    │       ├── run_tool(["nmap", "-sn", target])
    │       ├── run_tool(["fping", "-a", "-g", target])
    │       ├── Extract IPs via regex, merge, dedupe, sort
    │       └── Write live.txt → return list[str]
    │
    ├── Phase 3: Port Scanning (parallel per host)
    │   └── asyncio.gather(*[scan_host(ip, config, tree, sem) for ip in live_ips])
    │       └── portscan.scan_host(ip, config, tree, sem)
    │           ├── Try _run_nmap()   → parse_nmap_xml()    → Host with ports?
    │           ├── Try _run_naabu()  → parse_naabu_json()  → Host with ports?
    │           └── Try _run_masscan()→ parse_masscan_xml() → Host with ports?
    │           (stops at first scanner that finds open ports)
    │
    ├── Phase 4: Web Detection (parallel per host)
    │   └── asyncio.gather(*[probe_host(host, config, tree, sem) for host in hosts])
    │       └── webdetect.probe_host(host, config, tree, sem)
    │           └── For each open port:
    │               ├── aiohttp HEAD http://{ip}:{port}  (5s timeout)
    │               └── aiohttp HEAD https://{ip}:{port} (5s timeout, ssl=False)
    │           └── Populate host.web_endpoints with discovered URLs
    │
    ├── Phase 5: Vulnerability Scanning (parallel per host)
    │   └── asyncio.gather(*[scan_host_vulns(host, config, tree, sem) for host in hosts])
    │       └── vulnscan.scan_host_vulns(host, config, tree, sem)
    │           ├── asyncio.create_task(run_nuclei(host, config, tree))
    │           │   └── run_tool(["nuclei", "-l", targets, "-jsonl", "-o", out])
    │           │       └── parse_nuclei_json() → list[Finding]
    │           ├── asyncio.create_task(run_nmap_vuln(host, config, tree))
    │           │   └── run_tool(["nmap", "--script=vuln", "-p", ports, ip])
    │           │       └── parse_nmap_vuln_xml() → list[Finding]
    │           └── asyncio.gather(*tasks) → merge findings
    │
    └── Phase 6: Report Generation
        └── ReportEngine(config, tree).generate(report)
            ├── DocxRenderer.render()   → security_report.docx
            ├── XlsxRenderer.render()   → ports_summary.xlsx
            ├── HtmlRenderer.render()   → summary.html
            └── DashboardRenderer.render() → dashboard.html
```

---

## External Tools

Every external tool invocation with exact arguments:

### nmap — Network Mapper

**Host Discovery (Phase 2):**
```bash
nmap -sn <target> -oN <output.nmap>
```
- `-sn`: Ping scan only (no port scan)
- `-oN`: Normal text output
- Output parsed via regex for "Nmap scan report for" lines

**Port Scanning (Phase 3):**
```bash
nmap --open -p- -Pn -oA <output_base> <ip>
```
- `--open`: Show only open ports
- `-p-`: Scan all 65535 ports
- `-Pn`: Skip host discovery (assume up)
- `-oA`: Write all output formats (.nmap, .xml, .gnmap)
- XML output parsed by `parsers/nmap.py:parse_nmap_xml()`

**Vulnerability Scanning (Phase 5):**
```bash
nmap --script=vuln -p <port_csv> -Pn -oX <output.xml> <ip>
```
- `--script=vuln`: Run NSE vulnerability detection scripts
- `-p 22,80,443`: Scan only discovered open ports
- `-oX`: XML output only
- Parsed by `parsers/nmap.py:parse_nmap_vuln_xml()`

### fping — Fast Ping

**Host Discovery (Phase 2):**
```bash
fping -a -g <target>
```
- `-a`: Show alive hosts only
- `-g`: Generate target list from CIDR
- Output: one IP per line on stdout

### nuclei — Web Vulnerability Scanner

**Vulnerability Scanning (Phase 5):**
```bash
nuclei -l <targets.txt> -jsonl -o <output.json> -silent
```
- `-l`: Input file with one URL per line (from web detection phase)
- `-jsonl`: Output JSON Lines format
- `-o`: Output file path
- `-silent`: Suppress banner and non-essential output
- Parsed by `parsers/nuclei.py:parse_nuclei_json()`

### naabu — Fast Port Scanner (fallback)

**Port Scanning Fallback (Phase 3):**
```bash
naabu -host <ip> -json -o <output.json>
```
- `-host`: Target IP
- `-json`: JSON Lines output (one `{"ip","port","protocol"}` per line)
- `-o`: Output file
- Parsed by `parsers/naabu.py:parse_naabu_json()`

### masscan — Mass IP Port Scanner (fallback)

**Port Scanning Fallback (Phase 3):**
```bash
masscan <ip> -p0-65535 --rate 1000 -oX <output.xml>
```
- `-p0-65535`: Scan all ports
- `--rate 1000`: 1000 packets/second
- `-oX`: nmap-compatible XML output
- Parsed by `parsers/masscan.py:parse_masscan_xml()`

---

## Scanner Fallback Chain

When scanning ports for a host, the pipeline tries scanners in order and stops at the first one that finds open ports:

```
scan_host(ip)
    │
    ├─ 1. nmap (always runs, required tool)
    │     ├─ Found open ports? → RETURN Host
    │     └─ No ports → continue
    │
    ├─ 2. naabu (only if installed)
    │     ├─ Not installed? → SKIP
    │     ├─ Found open ports? → RETURN Host
    │     └─ No ports → continue
    │
    ├─ 3. masscan (only if installed)
    │     ├─ Not installed? → SKIP
    │     ├─ Found open ports? → RETURN Host
    │     └─ No ports → continue
    │
    └─ All scanners exhausted → RETURN Host with 0 ports
```

Tool availability is checked at runtime via `shutil.which()`. nmap is required (enforced in Phase 1 tool check). naabu and masscan are optional — if not installed, they're silently skipped.

The scanner list is defined in `pipeline/portscan.py`:
```python
_SCANNERS = [
    ("nmap",    _run_nmap,    "nmap"),
    ("naabu",   _run_naabu,   "naabu"),
    ("masscan", _run_masscan, "masscan"),
]
```

---

## Libraries & Dependencies

### pip Dependencies

| Library | Version | Where Used | Purpose |
|---------|---------|------------|---------|
| **typer[all]** | >=0.9 | `cli.py` | CLI framework with auto-generated help, argument parsing, shell completion |
| **rich** | >=13.0 | `cli.py`, `utils/process.py`, `utils/log.py` | Colored console output, progress indicators, `RichHandler` for logging |
| **python-docx** | >=1.1 | `reports/docx_renderer.py` | Generate .docx Word documents (tables, headings, colored text, page breaks) |
| **openpyxl** | >=3.1 | `reports/xlsx_renderer.py` | Generate .xlsx Excel workbooks (multiple sheets, cell data) |
| **jinja2** | >=3.1 | `reports/html_renderer.py`, `reports/dashboard.py` | HTML template rendering with autoescape |
| **aiohttp** | >=3.9 | `pipeline/webdetect.py` | Async HTTP client for web service probing (HEAD requests) |
| **pyyaml** | >=6.0 | `config.py` | Parse `wireghost.yml` config files |

### Dev Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| **pytest** | >=8.0 | Test framework |
| **pytest-asyncio** | >=0.23 | Async test support (`@pytest.mark.asyncio`) |

### Standard Library Usage

| Module | Where Used | Purpose |
|--------|------------|---------|
| `asyncio` | `pipeline/*`, `utils/process.py`, `cli.py` | Async subprocess execution, `gather()`, `Semaphore`, `create_subprocess_exec` |
| `xml.etree.ElementTree` | `parsers/nmap.py`, `parsers/masscan.py` | Parse nmap and masscan XML output |
| `json` | `parsers/nuclei.py`, `parsers/naabu.py`, `reports/dashboard.py` | Parse JSON/JSONL, serialize scan data for dashboard |
| `dataclasses` | `models/*`, `utils/fs.py`, `utils/process.py`, `config.py` | `@dataclass`, `field()` for typed data structures |
| `pathlib` | Everywhere | `Path` objects for all file operations |
| `logging` | Everywhere | Standard Python logger (`logging.getLogger("wireghost")`) |
| `re` | `models/severity.py`, `pipeline/discovery.py`, `utils/network.py` | IP extraction regex, severity keyword matching |
| `enum` | `models/severity.py` | `Severity(enum.Enum)` |
| `collections` | `models/report.py`, `parsers/naabu.py`, `parsers/masscan.py` | `defaultdict` for grouping ports by IP |
| `datetime` | `models/report.py`, `reports/*` | Timestamps for scan start/end, report generation time |
| `shutil` | `utils/process.py`, `pipeline/portscan.py`, `cli.py` | `shutil.which()` for tool availability checking |
| `urllib.parse` | `parsers/nuclei.py`, `utils/network.py` | `urlparse()` for URL decomposition |
| `importlib` | `reports/engine.py` | Dynamic import of renderer modules |
| `ssl` | `pipeline/webdetect.py` | SSL context with disabled verification for HTTPS probing |
| `typing` | Everywhere | `TYPE_CHECKING`, `Literal`, type hints |

---

## Data Models

All models are Python `@dataclass` classes in `src/wireghost/models/`.

### Severity (`models/severity.py`)

```python
class Severity(enum.Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"
    UNKNOWN  = "unknown"
```

**Associated constants:**
- `SEVERITY_ORDER` — `dict[Severity, int]` for sorting (CRITICAL=0 ... UNKNOWN=5)
- `SEVERITY_COLORS` — `dict[Severity, tuple[int,int,int]]` RGB tuples
- `SEVERITY_HEX` — `dict[Severity, str]` hex color strings for HTML/CSS

**Categorization function:**
```python
categorize_nmap_vuln(script_id: str, output: str) -> Severity
```
Keyword matching against combined `script_id + output` text:
- **CRITICAL:** shellshock, heartbleed, eternalblue, bluekeep, cve-2014-6271, cve-2014-0160, ms17-010
- **HIGH:** vuln, exploit, rce, remote-code-execution, sqli, xss, injection, buffer-overflow, privilege
- **MEDIUM:** weak, default, info-disclosure, information-disclosure, enum, brute, fuzz
- **INFO:** everything else

### Service (`models/scan.py`)

```
Service
  ├── name: str          # e.g. "http", "ssh", "mysql"
  ├── product: str = ""  # e.g. "nginx", "OpenSSH"
  └── version: str = ""  # e.g. "1.24", "8.9"
```

### Port (`models/scan.py`)

```
Port
  ├── number: int              # e.g. 80, 443, 22
  ├── protocol: str = "tcp"    # tcp or udp
  ├── state: str = "open"      # open, filtered, closed
  └── service: Service | None  # None for naabu/masscan (no service detection)
```

### Host (`models/scan.py`)

```
Host
  ├── ip: str                       # e.g. "192.168.1.1"
  ├── hostname: str = ""            # e.g. "web.local"
  ├── status: str = "up"
  ├── ports: list[Port] = []
  ├── web_endpoints: list[str] = [] # e.g. ["http://192.168.1.1:80", "https://192.168.1.1:443"]
  └── @property open_ports → list[Port]  # filters ports where state == "open"
```

### Finding (`models/finding.py`)

```
Finding
  ├── source: Literal["nmap_vuln", "nuclei", "nettacker"]
  ├── host: str             # IP address
  ├── port: str
  ├── protocol: str
  ├── severity: Severity
  ├── title: str            # e.g. "Nmap: http-enum" or "Apache Path Traversal"
  ├── description: str
  ├── endpoint: str = "/"   # URL path
  ├── full_url: str = ""
  ├── template_id: str = "" # nuclei template ID
  ├── script_id: str = ""   # nmap script ID
  ├── matched_at: str = ""  # nuclei matched-at URL
  ├── raw_output: str = ""  # raw tool output
  ├── references: list[str] = []  # CVE links, etc.
  └── tags: list[str] = []
```

### ScanReport (`models/report.py`)

```
ScanReport
  ├── target: str                    # e.g. "192.168.1.0/24"
  ├── hosts: list[Host] = []
  ├── findings: list[Finding] = []
  ├── scan_start: datetime
  ├── scan_end: datetime | None
  ├── severity_stats() → dict[Severity, int]         # count per severity
  ├── findings_by_severity() → dict[Severity, list[Finding]]
  ├── findings_by_host() → dict[str, list[Finding]]
  └── @property total_open_ports → int
```

### Utility Dataclasses

**RunResult** (`utils/process.py`):
```
RunResult
  ├── returncode: int
  ├── stdout: str
  └── stderr: str
```

**OutputTree** (`utils/fs.py`):
```
OutputTree
  ├── base: Path              # output/<target>/
  ├── live_host_dir: Path     # output/<target>/live_hosts/
  ├── web_dir: Path           # output/<target>/web/
  ├── reports_dir: Path       # output/<target>/reports/
  ├── ip_base: Path           # output/<target>/ips/
  ├── host_dir(ip) → Path
  ├── host_nmap_xml_dir(ip) → Path
  ├── host_web_dir(ip) → Path
  └── host_vuln_dir(ip) → Path
```

---

## Parsers

All parsers live in `src/wireghost/parsers/` and return model objects.

### nmap.py — Nmap XML Parser

| Function | Input | Output | Notes |
|----------|-------|--------|-------|
| `parse_nmap_xml(path)` | nmap port scan XML | `list[Host]` | Extracts IP, hostname, ports with service info |
| `parse_nmap_vuln_xml(path)` | nmap --script=vuln XML | `list[Finding]` | Creates Finding per script, uses `categorize_nmap_vuln()` |
| `extract_open_ports(path)` | nmap XML | `list[tuple[str, int]]` | (ip, port) pairs for open ports only |
| `generate_vuln_command(path, base)` | nmap XML | `str \| None` | Builds nmap vuln command string |

All functions return empty list/None on `FileNotFoundError` or `ParseError`.

### nuclei.py — Nuclei JSON Parser

| Function | Input | Output | Notes |
|----------|-------|--------|-------|
| `parse_nuclei_json(path)` | JSON array or JSONL | `list[Finding]` | Tries array first, falls back to line-by-line. Extracts severity from `info.severity`, endpoint from `matched-at` URL |

**JSON array format:**
```json
[{"template-id": "...", "info": {"name": "...", "severity": "high"}, "host": "...", "matched-at": "..."}]
```

**JSONL format:**
```
{"template-id": "...", "info": {"name": "...", "severity": "high"}, "host": "...", "matched-at": "..."}
{"template-id": "...", ...}
```

### naabu.py — Naabu JSONL Parser

| Function | Input | Output | Notes |
|----------|-------|--------|-------|
| `parse_naabu_json(path)` | JSONL | `list[Host]` | Groups ports by IP. No service detection (ports only) |

**Format:** `{"ip": "10.0.0.1", "port": 80, "protocol": "tcp"}`

### masscan.py — Masscan XML Parser

| Function | Input | Output | Notes |
|----------|-------|--------|-------|
| `parse_masscan_xml(path)` | nmap-compatible XML | `list[Host]` | Open ports only, no service detection |

---

## Async Concurrency Model

The pipeline uses `asyncio` for all I/O-bound operations (subprocess calls, HTTP requests).

### Parallelism Control

```python
sem = asyncio.Semaphore(config.parallelism)  # default: 10
```

Every per-host operation acquires the semaphore before starting:
```python
async def scan_host(ip, config, tree, sem):
    async with sem:  # limits concurrent hosts
        ...
```

### Phase Execution Pattern

Phases 3, 4, 5 all use the same pattern — parallel per-host with semaphore:
```python
# Launch all hosts concurrently, semaphore throttles to N at a time
results = await asyncio.gather(*[
    phase_fn(host, config, tree, sem) for host in hosts
])
```

### Within-Host Concurrency (Phase 5)

Nuclei and nmap vuln scans run **concurrently within the same host**:
```python
async with sem:
    tasks = []
    tasks.append(asyncio.create_task(run_nuclei(host, config, tree)))
    tasks.append(asyncio.create_task(run_nmap_vuln(host, config, tree)))
    results = await asyncio.gather(*tasks, return_exceptions=True)
```

### Subprocess Execution

All external tools run via `utils/process.py:run_tool()`:
```python
proc = await asyncio.create_subprocess_exec(
    *cmd,
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE,
)
stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
```

Timeout kills the process and returns `RunResult(returncode=-1)`.

---

## Configuration System

### Resolution Order (highest priority wins)

```
CLI flags  >  Environment variables  >  wireghost.yml  >  Defaults
```

### ScanConfig Fields

| Field | Type | Default | CLI Flag | Env Var |
|-------|------|---------|----------|---------|
| `target` | str | `""` | positional arg | `WIREGHOST_TARGET` |
| `output_dir` | Path | `./output` | `-o, --output` | `WIREGHOST_OUTPUT_DIR` |
| `parallelism` | int | `10` | `-j, --parallelism` | `WIREGHOST_PARALLELISM` |
| `skip_nuclei` | bool | `False` | `--skip-nuclei` | `WIREGHOST_SKIP_NUCLEI` |
| `skip_vuln` | bool | `False` | `--skip-vuln` | `WIREGHOST_SKIP_VULN` |
| `tool_timeout` | float | `3600.0` | `-t, --timeout` | `WIREGHOST_TOOL_TIMEOUT` |
| `report_formats` | list[str] | `["html","docx","xlsx"]` | `-f, --formats` | — |
| `report_title` | str | `"Security Assessment Summary Report"` | `--title` | `WIREGHOST_REPORT_TITLE` |
| `verbose` | bool | `False` | `-v, --verbose` | `WIREGHOST_VERBOSE` |

### YAML Config Example (`wireghost.yml`)

```yaml
output_dir: ./output
parallelism: 10
tool_timeout: 3600
report_formats:
  - html
  - docx
  - xlsx
report_title: "Security Assessment Summary Report"
```

### Loading Process (`ScanConfig.load()`)

1. Create `ScanConfig` with dataclass defaults
2. If `wireghost.yml` exists (or `--config` path), parse YAML and apply matching keys
3. Check `WIREGHOST_*` env vars, apply with type conversion (bool: `"1"/"true"/"yes"` → True)
4. Apply explicit keyword overrides from CLI flags
5. Ensure `output_dir` is a `Path` object

---

## Report System

### ReportEngine (`reports/engine.py`)

Dispatcher that routes `ScanReport` to format-specific renderers:

```python
engine = ReportEngine(config, tree)
paths = engine.generate(report)  # returns list[Path] of created files
```

Format mapping:
| Format | Renderer Class | Output File |
|--------|---------------|-------------|
| `"docx"` | `DocxRenderer` | `security_report.docx` |
| `"xlsx"` | `XlsxRenderer` | `ports_summary.xlsx` |
| `"html"` | `HtmlRenderer` | `summary.html` |
| `"dashboard"` | `DashboardRenderer` | `dashboard.html` |

Renderers are loaded via `importlib` dynamic import to avoid hard dependencies.

### DocxRenderer (`reports/docx_renderer.py`)

Uses `python-docx` to generate a Word document.

**Sections:**
1. **Title page** — report title (centered heading level 0), generation date, target
2. **Executive Summary** — risk assessment text (HIGH/MEDIUM/LOW based on critical+high count)
3. **Statistics table** — 6-row table (hosts, ports, total vulns, critical, high, medium) styled "Light Grid Accent 1"
4. **Vulnerability Breakdown** — table by source (Nmap vs Nuclei counts) styled "Light Grid Accent 2"
5. **Detailed Findings** — grouped by severity (CRITICAL → HIGH → MEDIUM → LOW → INFO), each finding has:
   - Heading with title
   - Color-coded severity badge via `RGBColor` from `SEVERITY_COLORS`
   - Detail table: host, endpoint, port, template_id, description, raw_output
6. **Recommendations** — dynamic list based on findings + general security advice

### XlsxRenderer (`reports/xlsx_renderer.py`)

Uses `openpyxl` to generate an Excel workbook.

**Sheets:**
1. **"Hosts and Ports"** — columns: Host, Open Ports (comma-separated)
2. **"Detailed Ports"** — columns: Host, Port, Protocol, State, Service

### HtmlRenderer (`reports/html_renderer.py`)

Uses `jinja2` to render `templates/static_report.html.j2`.

Self-contained HTML with inline CSS. Sections mirror the DOCX report:
- Stat card grid (hosts, ports, findings, critical, high, medium)
- Risk level badge (colored)
- Findings table with severity badges (`.badge-critical` through `.badge-info`)
- Per-host port tables
- Recommendations list

### DashboardRenderer (`reports/dashboard.py`)

Uses `jinja2` to render `templates/dashboard.html.j2` with embedded CSS and JavaScript.

**How it works:**
1. Reads `templates/assets/style.css` and `templates/assets/dashboard.js`
2. Serializes scan stats as JSON: `window.__SCAN_DATA__ = {...}`
3. Embeds CSS and JS inline in the HTML via `<style>{{ css }}</style>` and `<script>{{ js }}</script>`
4. Loads Chart.js from CDN: `https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js`

**Interactive features (dashboard.js):**
- **Severity chart** — Chart.js doughnut showing finding distribution
- **Filter buttons** — toggle severity levels on/off in the findings table
- **Search** — real-time text search across all findings
- **Host panels** — collapsible sections showing per-host port tables

**Theme:** Dark mode (#0d1117 background, #161b22 cards, #58a6ff accents, #30363d borders)

---

## Output Directory Structure

Created by `utils/fs.py:build_output_tree()`:

```
<output_dir>/<target_name>/
│
├── live_hosts/
│   └── live.txt                    # One IP per line, sorted
│
├── web/
│   └── all_endpoints.txt           # All discovered web URLs
│
├── ips/
│   └── <ip>/
│       ├── nmap_xml/
│       │   ├── portscan.xml        # nmap port scan XML
│       │   ├── portscan.nmap       # nmap text output
│       │   └── portscan.gnmap      # nmap grepable output
│       ├── web/
│       │   └── endpoints.txt       # Per-host web URLs
│       ├── vuln/
│       │   ├── nmap_vuln.xml       # nmap --script=vuln results
│       │   ├── nuclei.json         # nuclei JSONL findings
│       │   └── nuclei_targets.txt  # URLs fed to nuclei
│       ├── naabu_scan.json         # (if naabu fallback used)
│       └── masscan_scan.xml        # (if masscan fallback used)
│
├── reports/
│   ├── summary.html                # Static HTML report
│   ├── dashboard.html              # Interactive dashboard
│   ├── security_report.docx        # Word document
│   └── ports_summary.xlsx          # Excel workbook
│
└── wireghost.log                   # Scan log file
```

---

## Project File Map

```
src/wireghost/
├── __init__.py              # __version__ = "2.0.0"
├── __main__.py              # Entry: from wireghost.cli import app; app()
├── cli.py                   # Typer app: scan, report, config commands
├── config.py                # ScanConfig dataclass + layered loader
│
├── models/
│   ├── __init__.py          # Re-exports all models
│   ├── severity.py          # Severity enum, colors, categorize_nmap_vuln()
│   ├── scan.py              # Service, Port, Host
│   ├── finding.py           # Finding (unified vulnerability)
│   └── report.py            # ScanReport (aggregate with stats methods)
│
├── parsers/
│   ├── __init__.py
│   ├── nmap.py              # parse_nmap_xml, parse_nmap_vuln_xml, extract_open_ports
│   ├── nuclei.py            # parse_nuclei_json (array + JSONL)
│   ├── naabu.py             # parse_naabu_json (JSONL)
│   └── masscan.py           # parse_masscan_xml
│
├── pipeline/
│   ├── __init__.py
│   ├── orchestrator.py      # run_pipeline() — 6-phase async controller
│   ├── discovery.py         # Phase 2: nmap -sn + fping host discovery
│   ├── portscan.py          # Phase 3: fallback chain nmap → naabu → masscan
│   ├── webdetect.py         # Phase 4: async HTTP/HTTPS probing
│   └── vulnscan.py          # Phase 5: nuclei + nmap --script=vuln
│
├── reports/
│   ├── __init__.py          # Exports ReportEngine
│   ├── engine.py            # ReportEngine dispatcher
│   ├── docx_renderer.py     # DOCX report (python-docx)
│   ├── xlsx_renderer.py     # XLSX report (openpyxl)
│   ├── html_renderer.py     # Static HTML (jinja2)
│   ├── dashboard.py         # Interactive dashboard (jinja2 + Chart.js)
│   └── templates/
│       ├── static_report.html.j2
│       ├── dashboard.html.j2
│       └── assets/
│           ├── style.css    # Dark theme dashboard CSS
│           └── dashboard.js # Chart, filtering, search, host panels
│
└── utils/
    ├── __init__.py
    ├── process.py           # check_tools(), run_tool(), ToolMissing, RunResult
    ├── network.py           # safe_get(), extract_endpoint(), is_valid_ipv4()
    ├── fs.py                # OutputTree, build_output_tree()
    └── log.py               # setup_logging() with Rich + file handlers
```
