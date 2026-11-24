"""Phase 4 -- Vulnerability scanning via nuclei, nmap --script=vuln, and searchsploit."""

from __future__ import annotations

import asyncio
import logging
import shutil
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from wireghost.models.finding import Finding
from wireghost.models.scan import Host
from wireghost.parsers.getsploit import parse_getsploit_json
from wireghost.parsers.nmap import parse_nmap_vuln_xml
from wireghost.parsers.nuclei import parse_nuclei_json
from wireghost.parsers.searchsploit import parse_searchsploit_json
from wireghost.pipeline.cve_search import scan_cve_search
from wireghost.pipeline.nikto_scan import run_nikto
from wireghost.utils.process import run_tool

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.utils.fs import OutputTree

log = logging.getLogger("wireghost")

_HTTP_SERVICES = frozenset({"http", "http-alt", "http-proxy"})
_HTTPS_SERVICES = frozenset({"https", "ssl", "ssl/http", "ssl/https", "https-alt"})

# Workers extract the bundled template archives here at container start.  When
# a scan does not specify an explicit template directory, prefer this bundle
# over nuclei's built-in default subset.
BUNDLED_NUCLEI_TEMPLATES = Path("/opt/nuclei-external-templates")


def _build_nuclei_targets(host: Host) -> list[str]:
    """Build the nuclei target list for *host* — every open TCP port.

    Web endpoints keep their URL form; HTTP-like services get an http://
    URL, TLS-like services an https:// URL, and every other open TCP port
    gets nuclei's ``host:port`` network-target form.  Web endpoints that
    already cover a port are not duplicated.
    """
    targets: list[str] = []
    seen: set[str] = set()
    covered_ports: set[int] = set()
    for url in host.web_endpoints:
        if url and url not in seen:
            seen.add(url)
            targets.append(url)
        try:
            parsed = urlparse(url)
            if parsed.hostname == host.ip:
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                covered_ports.add(port)
        except ValueError:
            pass
    for port in host.open_ports:
        if not port.number or port.protocol not in ("", "tcp"):
            continue
        if port.number in covered_ports:
            continue
        service = (port.service_name or "").lower()
        if service in _HTTP_SERVICES:
            target = f"http://{host.ip}:{port.number}"
        elif service in _HTTPS_SERVICES:
            target = f"https://{host.ip}:{port.number}"
        else:
            target = f"{host.ip}:{port.number}"
        if target not in seen:
            seen.add(target)
            targets.append(target)
    return targets


def _collect_template_dirs(config: ScanConfig) -> list[Path]:
    """Return the list of template directories nuclei should scan."""
    if config.nuclei_templates:
        dirs: list[Path] = [Path(config.nuclei_templates)]
        if config.nuclei_default_templates:
            default_dir = Path.home() / "nuclei-templates"
            if default_dir.is_dir():
                dirs.append(default_dir)
        return dirs
    # No explicit template dir: use the worker's extracted bundle (full set)
    # instead of nuclei's built-in default subset.
    if BUNDLED_NUCLEI_TEMPLATES.is_dir():
        return [BUNDLED_NUCLEI_TEMPLATES]
    return []


def _glob_templates(dirs: list[Path]) -> list[str]:
    """Recursively collect all .yaml template files from *dirs*."""
    templates: list[str] = []
    for d in dirs:
        templates.extend(str(p) for p in d.rglob("*.yaml"))
    return sorted(set(templates))


async def run_nuclei(
    host: Host,
    config: ScanConfig,
    tree: OutputTree,
) -> list[Finding]:
    """Run nuclei against every open port on *host*."""
    targets = _build_nuclei_targets(host)
    if not targets:
        return []

    vuln_dir = tree.host_vuln_dir(host.ip)
    targets_file = vuln_dir / "nuclei_targets.txt"
    targets_file.write_text("\n".join(targets) + "\n", encoding="utf-8")

    base_cmd = [
        "nuclei",
        "-l",
        str(targets_file),
        "-jsonl",
        "-stats",
        "-severity",
        "critical,high,medium,low",
        "-etags",
        "brute-force,brute,login,fuzz",
    ]

    template_dirs = _collect_template_dirs(config)
    cmd = list(base_cmd)
    cmd.extend(["-o", str(vuln_dir / "nuclei.json")])
    for d in template_dirs:
        cmd.extend(["-t", str(d)])

    result = await run_tool(
        cmd,
        timeout=int(config.tool_timeout),
        label=f"nuclei {host.ip}",
    )
    if result.returncode != 0:
        log.warning("Nuclei failed for %s (rc=%d)", host.ip, result.returncode)

    findings = parse_nuclei_json(vuln_dir / "nuclei.json")
    if config.nuclei_templates:
        for f in findings:
            f.source = "nuclei_external"
    log.info("Nuclei %s: %d finding(s)", host.ip, len(findings))
    return findings


_SERVICE_SCRIPTS: dict[str, list[str]] = {
    "ssh": ["ssh-auth-methods", "ssh2-enum-algos", "ssh-hostkey"],
    "ms-sql": ["ms-sql-info", "ms-sql-config", "ms-sql-ntlm-info"],
    "mysql": ["mysql-info", "mysql-enum", "mysql-databases"],
    "rdp": ["rdp-enum-encryption", "rdp-ntlm-info"],
    "vnc": ["vnc-info", "vnc-brute"],
    "ftp": ["ftp-anon", "ftp-syst", "ftp-bounce"],
    "smtp": ["smtp-commands", "smtp-enum-users", "smtp-open-relay"],
    "dns": ["dns-zone-transfer", "dns-brute"],
    "rmi": ["rmi-dumpregistry"],
    "oracle": ["oracle-tns-version"],
    "memcached": ["memcached-info"],
    "redis": ["redis-info"],
    "mongodb": ["mongodb-info", "mongodb-databases"],
    "http": ["http-enum", "http-methods", "http-title"],
}


_BRUTE_SCRIPTS: set[str] = {
    "vnc-brute",
    "dns-brute",
    "http-brute",
    "ftp-brute",
    "smtp-brute",
    "pop3-brute",
    "imap-brute",
    "telnet-brute",
    "ssh-brute",
}


def _build_script_arg(host: Host, config: ScanConfig | None = None) -> str:
    """Build nmap --script argument with service-specific scripts added.

    When *config.skip_brute_force* is True, brute-force scripts are excluded.
    """
    skip_brute = config.skip_brute_force if config else False
    extra: set[str] = set()
    for port in host.open_ports:
        svc = port.service_name.lower().replace("-", "").replace("_", "")
        for key, scripts in _SERVICE_SCRIPTS.items():
            if key.replace("-", "") in svc:
                for script in scripts:
                    if skip_brute and script in _BRUTE_SCRIPTS:
                        continue
                    extra.add(script)

    base = "vuln,default"
    if extra:
        base += "," + ",".join(sorted(extra))
    return base


async def run_nmap_vuln(
    host: Host,
    config: ScanConfig,
    tree: OutputTree,
) -> list[Finding]:
    """Run nmap --script=vuln against open ports on *host*."""
    open_ports = host.open_ports
    if not open_ports:
        return []

    vuln_dir = tree.host_vuln_dir(host.ip)
    xml_path = vuln_dir / "nmap_vuln.xml"

    port_csv = ",".join(str(p.number) for p in open_ports)
    script_arg = _build_script_arg(host, config)

    result = await run_tool(
        [
            "nmap",
            f"--script={script_arg}",
            "-p",
            port_csv,
            "-Pn",
            "-oX",
            str(xml_path),
            host.ip,
        ],
        timeout=int(config.nmap_timeout or config.tool_timeout),
        label=f"nmap vuln {host.ip}",
    )

    if result.returncode != 0:
        log.warning("Nmap vuln failed for %s (rc=%d)", host.ip, result.returncode)

    findings = parse_nmap_vuln_xml(xml_path)
    log.info("Nmap vuln %s: %d finding(s)", host.ip, len(findings))
    return findings


def _collect_versions(host: Host) -> list[tuple[str, str]]:
    """Collect search terms for searchsploit with associated port.

    Returns list of (search_term, port_number) tuples.
    ONLY searches with version numbers to avoid false positives.
    e.g. "OpenSSH 9.6" not just "OpenSSH" (which returns exploits for all versions).
    """
    terms: list[tuple[str, str]] = []
    seen: set[str] = set()

    _SKIP = {
        "linux",
        "ubuntu",
        "debian",
        "windows",
        "http",
        "https",
        "tcp",
        "udp",
        "http-proxy",
        "unknown",
        "ppp",
    }

    # From nmap -sV — ONLY when version is detected
    for port in host.open_ports:
        if port.service and port.service.product and port.service.version:
            name = port.service.product
            if name.lower() in _SKIP:
                continue
            port_str = str(port.number)
            # Extract major.minor version only (e.g. "9.6" from "9.6p1 Ubuntu 3ubuntu13.15")
            import re

            ver_match = re.search(r"(\d+\.\d+)", port.service.version)
            if ver_match:
                short_ver = ver_match.group(1)
                key = f"{name} {short_ver}"
                if key not in seen:
                    seen.add(key)
                    terms.append((key, port_str))

    # From httpx tech-detect (WebTech) — with version
    for tech in host.technologies:
        if tech.name and tech.name.lower() not in _SKIP and tech.version:
            key = f"{tech.name} {tech.version}"
            # Try to find port from URL
            port_str = ""
            if tech.url:
                import re

                m = re.search(r":(\d+)", tech.url)
                if m:
                    port_str = m.group(1)
            if key not in seen:
                seen.add(key)
                terms.append((key, port_str))

    return sorted(terms)


async def run_searchsploit(
    host: Host,
    config: ScanConfig,
    tree: OutputTree,
) -> list[Finding]:
    """Run searchsploit with version-aware searches."""
    if not shutil.which("searchsploit"):
        return []

    vuln_dir = tree.host_vuln_dir(host.ip)
    all_findings: list[Finding] = []
    seen_edb: set[str] = set()

    # Method 1: searchsploit --nmap (basic, uses nmap XML with -sV data)
    nmap_xml = tree.host_nmap_xml_dir(host.ip) / "portscan.xml"
    if nmap_xml.exists():
        result = await run_tool(
            ["searchsploit", "-v", "--nmap", str(nmap_xml), "-j"],
            timeout=int(config.tool_timeout),
            label=f"searchsploit:nmap {host.ip}",
        )
        output = result.stdout.strip()
        if output:
            json_out = vuln_dir / "searchsploit_nmap.json"
            json_out.write_text(output, encoding="utf-8")
            findings = parse_searchsploit_json(json_out, host_ip=host.ip)
            for f in findings:
                if f.template_id not in seen_edb:
                    seen_edb.add(f.template_id)
                    all_findings.append(f)

    # Method 2: Per-version searches (more targeted, with port mapping)
    import json as json_mod

    version_tuples = _collect_versions(host)
    combined_exploits: list[dict] = []
    # Track which port each exploit came from
    exploit_ports: dict[str, str] = {}  # EDB-ID → port

    for software, port_str in version_tuples:
        result = await run_tool(
            ["searchsploit", "-s", "-j", software],
            timeout=30,
            label=f"searchsploit:{software}",
        )
        output = result.stdout.strip()
        if not output:
            continue
        try:
            data = json_mod.loads(output)
            for entry in data.get("RESULTS_EXPLOIT", []):
                edb = str(entry.get("EDB-ID", ""))
                if edb and edb not in exploit_ports:
                    exploit_ports[edb] = port_str
                combined_exploits.append(entry)
        except json_mod.JSONDecodeError as exc:
            log.warning("Failed to parse searchsploit output for %s: %s", software, exc)

    # Save ALL accumulated results as one JSON file
    if combined_exploits:
        combined = {"RESULTS_EXPLOIT": combined_exploits, "RESULTS_SHELLCODE": []}
        json_path = vuln_dir / "searchsploit_all.json"
        json_path.write_text(json_mod.dumps(combined), encoding="utf-8")
        findings = parse_searchsploit_json(json_path, host_ip=host.ip)
        # Set port on each finding based on which service matched
        for f in findings:
            edb = f.template_id.replace("EDB-", "")
            if edb in exploit_ports:
                f.port = exploit_ports[edb]
        for f in findings:
            if f.template_id not in seen_edb:
                seen_edb.add(f.template_id)
                all_findings.append(f)

    log.info(
        "Searchsploit %s: %d exploit(s) from %d version(s)",
        host.ip,
        len(all_findings),
        len(version_tuples),
    )
    return all_findings


async def run_getsploit(
    host: Host,
    config: ScanConfig,
    tree: OutputTree,
) -> list[Finding]:
    """Run getsploit (Vulners API) exploit search for detected services.

    Queries Vulners across Exploit-DB, Metasploit, Packetstorm, and more.
    Requires either ``vulners_api_key`` in config or ``VULNERS_API_KEY`` env var.
    """
    if config.skip_getsploit:
        return []
    if not shutil.which("getsploit"):
        log.info("getsploit not found — skipping Vulners exploit search")
        return []

    import os

    api_key = config.vulners_api_key or os.environ.get("VULNERS_API_KEY", "")
    if not api_key:
        log.warning("VULNERS_API_KEY not set — skipping getsploit")
        return []

    vuln_dir = tree.host_vuln_dir(host.ip)
    all_findings: list[Finding] = []
    seen_ids: set[str] = set()

    version_tuples = _collect_versions(host)

    for software, port_str in version_tuples:
        cmd = ["getsploit", "-j", "-c", "5", software, "-k", api_key]

        result = await run_tool(
            cmd,
            timeout=30,
            label=f"getsploit:{software}",
        )
        output = result.stdout.strip()
        if not output:
            continue

        findings = parse_getsploit_json(output, host_ip=host.ip)
        for f in findings:
            if port_str:
                f.port = port_str
            if f.template_id not in seen_ids:
                seen_ids.add(f.template_id)
                all_findings.append(f)

    # Save combined results as JSON for traceability
    import json as json_mod

    if all_findings:
        combined: list[dict] = []
        for f in all_findings:
            combined.append(
                {
                    "id": f.template_id,
                    "title": f.title,
                    "port": f.port,
                    "severity": f.severity.value,
                    "references": f.references,
                }
            )
        json_path = vuln_dir / "getsploit_all.json"
        json_path.write_text(json_mod.dumps(combined, indent=2), encoding="utf-8")

    log.info(
        "Getsploit %s: %d exploit(s) from %d version(s)",
        host.ip,
        len(all_findings),
        len(version_tuples),
    )
    return all_findings


async def scan_host_vulns(host: Host, config: ScanConfig, tree: OutputTree) -> list[Finding]:
    """Run nuclei, nmap vuln, and searchsploit concurrently for a single host.

    *sem* limits how many hosts are scanned in parallel.
    """
    tasks: list[asyncio.Task[list[Finding]]] = []

    if not config.skip_nuclei:
        tasks.append(asyncio.create_task(run_nuclei(host, config, tree)))

    if not config.skip_vuln:
        tasks.append(asyncio.create_task(run_nmap_vuln(host, config, tree)))

    # Searchsploit: auto-find exploits for detected services (if installed)
    tasks.append(asyncio.create_task(run_searchsploit(host, config, tree)))

    # Getsploit: Vulners API exploit search (Exploit-DB + Metasploit + Packetstorm + more)
    if not config.skip_getsploit:
        tasks.append(asyncio.create_task(run_getsploit(host, config, tree)))

    # Nikto: web server misconfiguration scanner (if enabled and web endpoints exist)
    if not config.skip_nikto and host.web_endpoints:
        tasks.append(asyncio.create_task(run_nikto(host, config, tree)))

    # NVD CVE search (first pass): uses structured version data from nmap -sV
    # and httpx. Second pass in orchestrator adds enumeration-tool findings.
    tasks.append(asyncio.create_task(scan_cve_search(host, [], config)))

    if not tasks:
        return []

    results = await asyncio.gather(*tasks, return_exceptions=True)

    findings: list[Finding] = []
    for result in results:
        if isinstance(result, BaseException):
            log.error("Vuln scan error for %s: %s", host.ip, result, exc_info=result)
        else:
            findings.extend(result)

    log.info(
        "Vuln scan %s: %d total finding(s)",
        host.ip,
        len(findings),
    )
    return findings
