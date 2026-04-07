# Wire_Ghost Rewrite Design Spec

## Context

Wire_Ghost is a security scanning orchestration toolkit that chains nmap, nuclei, dirsearch, fping, and httpx into a parallel pipeline and generates DOCX/XLSX reports. The current codebase has severe duplication problems (nmap XML parsing reimplemented 7 times, utility functions copy-pasted across files, 3 variants of the report generator) and is hard to maintain. This rewrite keeps the same scanning flow while producing cleaner, modular Python code and adding new capabilities.

## Goals

1. Replace all bash orchestration with a pure Python CLI
2. Eliminate code duplication via shared parsers and typed data models
3. Add HTML report output (static + interactive dashboard)
4. Add a proper CLI with subcommands
5. Add Docker Compose multi-container setup
6. Make output paths configurable (default `./output/`)

## Non-Goals

- Changing the scanning methodology or tool selection
- Building a web UI or server-based dashboard
- Supporting Windows

---

## 1. Project Layout

```
wireghost/
    pyproject.toml
    README.md
    Dockerfile
    docker-compose.yml
    wireghost.example.yml          # example config

    src/
        wireghost/
            __init__.py
            __main__.py             # python -m wireghost
            cli.py                  # typer CLI app
            config.py               # ScanConfig dataclass, YAML/CLI/env loading

            pipeline/
                __init__.py
                orchestrator.py     # main async pipeline controller
                discovery.py        # Phase 1: nmap -sn + fping
                portscan.py         # Phase 2: nmap -p- per host
                webdetect.py        # Phase 3: HTTP/HTTPS probing
                vulnscan.py         # Phase 4: nuclei + nmap --script=vuln

            parsers/
                __init__.py
                nmap.py             # single nmap XML parser
                nuclei.py           # nuclei JSON parser (array + JSONL)
                nettacker.py        # nettacker JSON parser (optional)

            models/
                __init__.py
                scan.py             # Host, Port, Service dataclasses
                finding.py          # Finding dataclass (unified vuln representation)
                severity.py         # Severity enum, colors, categorization
                report.py           # ScanReport aggregate dataclass

            reports/
                __init__.py
                engine.py           # ReportEngine: dispatches to renderers
                docx_renderer.py    # DOCX (python-docx)
                xlsx_renderer.py    # XLSX (openpyxl)
                html_renderer.py    # static HTML (Jinja2)
                dashboard.py        # interactive dashboard (Jinja2 + JS)
                templates/
                    static_report.html.j2
                    dashboard.html.j2
                    dashboard_assets/
                        style.css
                        dashboard.js

            utils/
                __init__.py
                subprocess.py       # async subprocess runner
                logging.py          # rich console + file logging
                network.py          # safe_get, IP validation, URL helpers
                fs.py               # output directory management

    tests/
        conftest.py
        fixtures/
            nmap_port_scan.xml
            nmap_vuln_scan.xml
            nuclei_results.json
            nuclei_results.jsonl
        test_parsers/
            test_nmap.py
            test_nuclei.py
        test_models/
            test_severity.py
        test_pipeline/
            test_discovery.py
        test_reports/
            test_engine.py
```

---

## 2. Data Models

### Severity (`models/severity.py`)

Single source of truth for severity logic, replacing duplication across 4+ files.

```python
class Severity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

SEVERITY_ORDER: dict[Severity, int]          # for sorting
SEVERITY_COLORS: dict[Severity, tuple[int,int,int]]  # RGB, format-agnostic
SEVERITY_HEX: dict[Severity, str]            # for HTML/CSS
SEVERITY_DOCX: dict[Severity, RGBColor]      # lazy-computed from SEVERITY_COLORS

def categorize_nmap_vuln(script_id: str, output: str) -> Severity:
    """Merged keyword lists from end.py and port_vuln.py."""
```

### Scan Data (`models/scan.py`)

```python
@dataclass
class Service:
    name: str
    product: str = ""
    version: str = ""

@dataclass
class Port:
    number: int
    protocol: str      # tcp/udp
    state: str         # open, filtered, etc.
    service: Service | None = None

@dataclass
class Host:
    ip: str
    hostname: str = ""
    status: str = "up"
    ports: list[Port] = field(default_factory=list)
    web_endpoints: list[str] = field(default_factory=list)
```

### Finding (`models/finding.py`)

Replaces the ad-hoc dicts currently used across all files.

```python
@dataclass
class Finding:
    source: Literal["nmap_vuln", "nuclei", "nettacker"]
    host: str
    port: str
    protocol: str
    severity: Severity
    title: str
    description: str
    endpoint: str = "/"
    full_url: str = ""
    template_id: str = ""
    script_id: str = ""
    matched_at: str = ""
    raw_output: str = ""
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
```

### ScanReport (`models/report.py`)

```python
@dataclass
class ScanReport:
    target: str
    hosts: list[Host]
    findings: list[Finding]
    scan_start: datetime
    scan_end: datetime | None = None

    def severity_stats(self) -> dict[Severity, int]: ...
    def findings_by_severity(self) -> dict[Severity, list[Finding]]: ...
    def findings_by_host(self) -> dict[str, list[Finding]]: ...
```

---

## 3. Parsers

### `parsers/nmap.py`

One parser replaces 7 current implementations. Exports:

- `parse_nmap_xml(path) -> list[Host]` -- port scan results
- `parse_nmap_vuln_xml(path) -> list[Finding]` -- vuln scan results
- `extract_open_ports(path) -> list[tuple[str, int]]` -- IP/port pairs
- `generate_vuln_command(xml_path, output_base) -> str | None` -- replaces nmap_parser.py

### `parsers/nuclei.py`

Consolidates dual-format handling from `end.py` and `nuclei.py`. Exports:

- `parse_nuclei_json(path) -> list[Finding]` -- handles JSON array and JSONL

### `parsers/nettacker.py`

- `parse_nettacker_json(path) -> list[Finding]` -- optional, skipped if no output

---

## 4. Pipeline Architecture

Uses `asyncio` with `asyncio.create_subprocess_exec`. The workload is I/O-bound (waiting for subprocess completion), making asyncio ideal. `asyncio.Semaphore(config.parallelism)` replaces `xargs -P10`.

### Orchestrator Flow

```python
async def run_pipeline(config: ScanConfig) -> ScanReport:
    # Phase 1: Host Discovery (nmap -sn + fping, merge, dedupe)
    live_hosts: list[str] = await discovery.discover_hosts(config)

    # Phase 2: Port Scan (parallel per host, semaphore-limited)
    sem = asyncio.Semaphore(config.parallelism)
    hosts: list[Host] = await asyncio.gather(*[
        portscan.scan_host(ip, config, sem) for ip in live_hosts
    ])

    # Phase 3: Web Detection (async HTTP/HTTPS probing per host)
    await asyncio.gather(*[
        webdetect.probe_host(host, config, sem) for host in hosts
    ])

    # Phase 4: Vuln Scanning (nuclei + nmap --script=vuln, parallel per host)
    findings: list[Finding] = []
    await asyncio.gather(*[
        vulnscan.scan_host(host, config, sem, findings) for host in hosts
    ])

    # Phase 5: Report Generation
    report = ScanReport(target=config.target, hosts=hosts, findings=findings, ...)
    ReportEngine(config).generate(report)
    return report
```

### Phase Modules

Each phase follows the same pattern: receive config + semaphore, run external tools via `utils/subprocess.run_tool()`, parse output via `parsers/`, return model objects.

---

## 5. CLI Design

Using `typer` for type-annotated CLI arguments.

```
wireghost scan <target>
    --output-dir PATH          # default: ./output/
    --parallelism INT          # default: 10
    --skip-nuclei              # skip nuclei phase
    --skip-vuln                # skip nmap vuln phase
    --timeout FLOAT            # per-tool timeout (seconds), default: 3600
    --report-formats LIST      # default: html,docx,xlsx
    -v / --verbose

wireghost report <scan-dir>
    --output-dir PATH
    --formats LIST             # html,docx,xlsx,dashboard
    --title TEXT

wireghost config init          # create wireghost.yml template
wireghost config show          # print resolved config
```

### Config Resolution

Priority (later overrides earlier):
1. Built-in defaults in `config.py`
2. `wireghost.yml` in CWD (if present)
3. Environment variables (`WIREGHOST_OUTPUT_DIR`, etc.)
4. CLI flags

```python
@dataclass
class ScanConfig:
    target: str
    output_dir: Path = Path("./output")
    parallelism: int = 10
    skip_nuclei: bool = False
    skip_vuln: bool = False
    tool_timeout: float = 3600.0
    report_formats: list[str] = field(default_factory=lambda: ["html", "docx", "xlsx"])
    report_title: str = "Security Assessment Summary Report"
    verbose: bool = False
```

---

## 6. Report System

### Engine (`reports/engine.py`)

```python
class ReportEngine:
    def __init__(self, config: ScanConfig):
        self.renderers = {
            "docx": DocxRenderer(),
            "xlsx": XlsxRenderer(),
            "html": HtmlRenderer(),
            "dashboard": DashboardRenderer(),
        }

    def generate(self, report: ScanReport) -> list[Path]:
        """Generate all requested formats. Returns paths to created files."""
```

All renderers implement: `render(report: ScanReport, config: ScanConfig) -> Path`

### DocxRenderer

Ports the report generation logic from current `end.py`. Operates on `ScanReport` model, not raw XML. Sections: title page, executive summary, severity stats table, vulnerability breakdown by source, discovered endpoints, detailed findings grouped by severity, recommendations.

### XlsxRenderer

Ports `xml_to_xlsx.py`. Two sheets: "Hosts and Ports" summary, "Detailed Ports" per-host breakdown.

### HtmlRenderer

Jinja2 template producing a single self-contained HTML file with inline CSS. Content mirrors the DOCX report structure.

### DashboardRenderer

Jinja2 template producing a single HTML file with embedded JavaScript:
- Severity distribution chart (Chart.js via CDN with graceful fallback)
- Filterable/sortable findings table (vanilla JS)
- Per-host collapsible panels
- Severity toggle buttons
- Full-text search across findings
- `ScanReport` serialized as embedded JSON blob -- all interactivity is client-side

---

## 7. Docker Compose

### Container Layout

```yaml
services:
  wireghost:
    build: .
    volumes:
      - scan-data:/data/output
      - ./wireghost.yml:/app/wireghost.yml:ro
    environment:
      - WIREGHOST_OUTPUT_DIR=/data/output
    entrypoint: ["python", "-m", "wireghost"]

  nmap:
    image: instrumentisto/nmap:latest
    volumes: [scan-data:/data/output]
    network_mode: host
    profiles: ["tools"]

  nuclei:
    image: projectdiscovery/nuclei:latest
    volumes: [scan-data:/data/output]
    network_mode: host
    profiles: ["tools"]

  httpx:
    image: projectdiscovery/httpx:latest
    volumes: [scan-data:/data/output]
    network_mode: host
    profiles: ["tools"]

volumes:
  scan-data:
```

### Dockerfile

Single container with Python + all tools pre-installed (nmap, fping, nuclei, httpx). The multi-container tool profiles are optional for distributed mode.

Usage: `docker compose run wireghost scan 192.168.1.0/24`

---

## 8. Output Directory Structure

Preserved from current layout, rooted at configurable `output_dir`:

```
{output_dir}/{target_dir}/
    all/
        live_host/live.txt
        web/web.txt
    ip/{ip}/
        nmap/xml/
        nmap/docx/
        web/nuclei/
        vuln/
    reports/
        summary.html
        dashboard.html
        {ip}_report.docx
        {ip}_ports.xlsx
```

---

## 9. Dependencies

```toml
[project]
requires-python = ">=3.12"
dependencies = [
    "typer>=0.9",
    "rich>=13.0",
    "python-docx>=1.1",
    "openpyxl>=3.1",
    "jinja2>=3.1",
    "aiohttp>=3.9",
    "pyyaml>=6.0",
]

[project.optional-dependencies]
dev = ["pytest>=8.0", "pytest-asyncio>=0.23"]

[project.scripts]
wireghost = "wireghost.cli:app"
```

---

## 10. Implementation Sequence

### Phase A: Foundation (blocks everything else)
1. `pyproject.toml` + project scaffolding
2. `models/severity.py`, `models/scan.py`, `models/finding.py`, `models/report.py`
3. `parsers/nmap.py` (single nmap parser)
4. `parsers/nuclei.py`
5. `utils/subprocess.py`, `utils/network.py`, `utils/fs.py`, `utils/logging.py`
6. Tests for parsers + models using fixture files

### Phase B: Pipeline (depends on A)
7. `pipeline/discovery.py`
8. `pipeline/portscan.py`
9. `pipeline/webdetect.py`
10. `pipeline/vulnscan.py`
11. `pipeline/orchestrator.py`
12. `cli.py` with `scan` subcommand
13. End-to-end test

### Phase C: Reports (depends on A, partially parallel with B)
14. `reports/docx_renderer.py` (port end.py logic)
15. `reports/xlsx_renderer.py` (port xml_to_xlsx.py logic)
16. `reports/html_renderer.py` + Jinja2 template
17. `reports/dashboard.py` + Jinja2 template + JS assets
18. `reports/engine.py`
19. `cli.py` `report` subcommand

### Phase D: Packaging (depends on B + C)
20. `config.py` with YAML loading
21. `cli.py` `config` subcommands
22. `__main__.py`
23. `Dockerfile`
24. `docker-compose.yml`
25. `wireghost.example.yml`

---

## 11. Verification

1. **Parser tests**: Run parsers against fixture XML/JSON files extracted from current `script/docx/output.json` and sample nmap output. Verify Host/Finding objects match expected values.
2. **Pipeline smoke test**: Run `wireghost scan` against a known test target (local VM or loopback). Verify all phases complete and output directory structure matches spec.
3. **Report comparison**: Generate DOCX from same scan data with both old `end.py` and new `DocxRenderer`. Compare content sections manually for parity.
4. **HTML reports**: Open static HTML and dashboard in browser. Verify severity chart renders, filtering works, findings match DOCX content.
5. **Docker**: `docker compose build && docker compose run wireghost scan 127.0.0.1` -- verify container starts, tools are available, output is written to shared volume.
6. **CLI**: Test all subcommands: `wireghost scan`, `wireghost report`, `wireghost config init`, `wireghost config show`.
