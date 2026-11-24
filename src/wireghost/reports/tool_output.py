"""Collect per-tool findings and raw output for reports."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from wireghost.models.report import ScanReport

# Every tool the pipeline can run.  Tools without dedicated raw files still
# appear in the report (their evidence lives in Finding.raw_output/description).
TOOL_SPECS: list[dict] = [
    {
        "source": "nmap",
        "label": "Nmap (port scan)",
        "command": "nmap --open -p<port_range> -Pn --host-timeout 1h -oA <out_base> <ip>",
        "globs": ["nmap_xml/portscan.nmap", "nmap_xml/portscan.xml", "nmap_xml/portscan.gnmap"],
    },
    {
        "source": "nmap_vuln",
        "label": "Nmap NSE (vuln scripts)",
        "command": "nmap --script=vuln -p <ports> -oX <xml> <ip>",
        "globs": ["vuln/nmap_vuln.xml"],
    },
    {
        "source": "nuclei",
        "label": "Nuclei",
        "command": (
            "nuclei -l nuclei_targets.txt -jsonl -stats "
            "-severity critical,high,medium,low "
            "-etags brute-force,brute,login,fuzz "
            "-o nuclei.json -t <template_dir>"
        ),
        "globs": ["vuln/nuclei_targets.txt", "vuln/nuclei.json"],
        "aliases": ["nuclei_external"],
    },
    {
        "source": "msf_scan",
        "label": "Metasploit Framework",
        "command": "msfconsole -q -r msf_scan.rc",
        "globs": ["vuln/msf_scan.rc", "vuln/msf_spool.txt"],
    },
    {
        "source": "nikto",
        "label": "Nikto",
        "command": "nikto -h <url> -o <file> -Format json -no404 -Tuning 1234589ab",
        "globs": ["vuln/nikto_*.json"],
    },
    {
        "source": "sslscan",
        "label": "sslscan",
        "command": "sslscan --xml=<xml> <ip>:<port>",
        "globs": ["vuln/sslscan_*.xml"],
    },
    {
        "source": "enum4linux",
        "label": "enum4linux",
        "command": "enum4linux -a <ip>",
        "globs": ["vuln/enum4linux.txt"],
    },
    {
        "source": "netexec",
        "label": "NetExec (nxc)",
        "command": "nxc <proto> <ip> --no-bruteforce --timeout 30",
        "globs": ["vuln/nxc_*.txt"],
    },
    {
        "source": "snmp_enum",
        "label": "SNMP enumeration",
        "command": "snmpwalk -v2c -c <community> -OQn <ip>",
        "globs": ["vuln/snmpwalk.txt"],
    },
    {
        "source": "nfs_enum",
        "label": "NFS enumeration",
        "command": "showmount -e <ip>",
        "globs": ["vuln/showmount.txt"],
    },
    {
        "source": "ldap_enum",
        "label": "LDAP enumeration",
        "command": 'ldapsearch -x -H ldap[s]://<ip>:<port> -b "" -s base',
        "globs": ["vuln/ldapsearch_rootdse_*.txt"],
    },
    {
        "source": "httpx",
        "label": "httpx",
        "command": "httpx -l <endpoints> -tech-detect -sc -title -server -favicon -jarm -json -o <json> -silent",
        "globs": ["web/tech_detect.json"],
    },
    {
        "source": "katana",
        "label": "katana",
        "command": "katana -u <url> -d 3 -jc -kf -ef css,png,jpg,gif,svg,woff,woff2,ico,ttf,eot -silent -nc",
        "globs": ["web/katana_*.txt"],
    },
    {
        "source": "gowitness",
        "label": "gowitness",
        "command": "gowitness scan file <urls_file> --screenshot-format png",
        "globs": ["web/screenshots/*.png"],
    },
    {
        "source": "searchsploit",
        "label": "searchsploit",
        "command": "searchsploit <product> <version>",
        "globs": [],
    },
    {
        "source": "getsploit",
        "label": "getsploit (Vulners)",
        "command": "getsploit -j -c 5 <software> -k <vulners_api_key>",
        "globs": [],
    },
    {
        "source": "nvd",
        "label": "NVD CVE lookup",
        "command": "(NVD API lookup of detected product versions)",
        "globs": [],
    },
    {
        "source": "service_enum",
        "label": "service_enum (pure Python)",
        "command": "(TCP banner/response probes per open service)",
        "globs": [],
    },
]


def _norm_source(source: str) -> str:
    return "nuclei" if source in ("nuclei", "nuclei_external") else source


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def collect_tool_outputs(report: ScanReport, reports_dir: Path) -> list[dict]:
    """Return per-tool findings + every raw output file (full text).

    Results are cached on the report object so the four renderers only read
    the (potentially very large) raw files once.
    """
    cache_key = str(reports_dir)
    cached = getattr(report, "_tool_outputs_cache", None)
    if cached is not None and cached[0] == cache_key:
        return cached[1]

    ips_root = Path(reports_dir).parent / "ips"
    findings_by_source: dict[str, list] = defaultdict(list)
    for finding in report.findings:
        findings_by_source[_norm_source(finding.source)].append(finding)

    host_ips = sorted({h.ip for h in report.hosts})

    results: list[dict] = []
    for spec in TOOL_SPECS:
        source = spec["source"]
        findings = findings_by_source.get(source, [])
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            sev = getattr(finding.severity, "value", str(finding.severity))
            if sev in severity_counts:
                severity_counts[sev] += 1

        files: list[dict] = []
        for host in host_ips:
            host_dir = ips_root / host
            if not host_dir.is_dir():
                continue
            for pattern in spec.get("globs", []):
                for path in sorted(host_dir.glob(pattern)):
                    try:
                        size = path.stat().st_size
                    except OSError:
                        continue
                    binary = path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif"}
                    files.append(
                        {
                            "host": host,
                            "name": path.name,
                            "path": str(path.relative_to(ips_root.parent)),
                            "size": size,
                            "binary": binary,
                            "text": "" if binary else _read_text(path),
                        }
                    )

        file_hosts = {f["host"] for f in files}
        finding_hosts = {str(f.host) for f in findings}
        results.append(
            {
                "source": source,
                "label": spec["label"],
                "command": spec["command"],
                "status": "ran" if files or findings else "no output",
                "findings": findings,
                "finding_count": len(findings),
                "severity_counts": severity_counts,
                "hosts": sorted(file_hosts | finding_hosts),
                "files": files,
            }
        )

    report._tool_outputs_cache = (cache_key, results)
    return results
