"""Scan configuration with layered loading: defaults -> YAML -> env -> overrides."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class ScanConfig:
    """Configuration for a Wire_Ghost scan run.

    Values are resolved in priority order (highest wins):
    1. Explicit keyword overrides
    2. Environment variables (WIREGHOST_*)
    3. YAML config file (wireghost.yml)
    4. Dataclass defaults
    """

    target: str = ""
    output_dir: Path = field(default_factory=lambda: Path("./output"))
    parallelism: int = 10
    version_detect: bool = True
    os_detect: bool = True
    service_enum: bool = True
    skip_nuclei: bool = False
    skip_vuln: bool = False
    tool_timeout: float = 3600.0
    # nmap-specific budget. Nmap is routinely the slowest tool (full -sV -O
    # followed by --script=vuln on a /24 can blow past the generic 1 h),
    # so it gets 1.5 h by default. Other tools stay on tool_timeout.
    nmap_timeout: float = 5400.0
    report_formats: list[str] = field(
        default_factory=lambda: ["html", "docx", "xlsx"]
    )
    report_title: str = "Security Assessment Summary Report"
    verbose: bool = False
    logo_path: Path | None = None
    nuclei_templates: str = ""
    nuclei_default_templates: bool = True
    nuclei_batch_size: int = 5000
    skip_screenshots: bool = False
    # When True, hosts that fail ICMP discovery are STILL port-scanned
    # (nmap -Pn already bypasses ping). Useful against firewalled targets
    # that drop ICMP but have open TCP ports; expensive on large CIDRs
    # because every IP in the range becomes a scan target.
    scan_unresponsive: bool = False
    skip_enum4linux: bool = False
    skip_nikto: bool = False
    skip_netexec: bool = False
    skip_arp_scan: bool = False
    skip_tls_audit: bool = False
    skip_snmp_enum: bool = False
    skip_nfs_enum: bool = False
    skip_ldap_enum: bool = False
    skip_web_crawl: bool = False
    skip_msf_scan: bool = False
    skip_brute_force: bool = False
    msf_metadata_path: str = "/opt/msf/modules_metadata_base.json"

    @classmethod
    def load(
        cls,
        target: str = "",
        config_path: str | Path | None = None,
        **overrides: object,
    ) -> ScanConfig:
        """Build a config by layering defaults, YAML, env vars, and overrides.

        Parameters
        ----------
        target:
            Target specification (IP, CIDR, hostname).
        config_path:
            Explicit path to a YAML config file.  When *None* the loader
            looks for ``wireghost.yml`` in the current directory.
        **overrides:
            Keyword arguments that take highest priority.
        """
        cfg = cls()

        # --- 1. YAML file ---
        yaml_data = _load_yaml(config_path)
        if yaml_data:
            _apply_yaml(cfg, yaml_data)

        # --- 2. Environment variables ---
        _apply_env(cfg)

        # --- 3. Explicit overrides ---
        if target:
            cfg.target = target
        for key, value in overrides.items():
            if value is None:
                continue
            if hasattr(cfg, key):
                expected = type(getattr(cfg, key))
                if expected is Path and not isinstance(value, Path):
                    value = Path(str(value))
                setattr(cfg, key, value)

        cfg.output_dir = Path(cfg.output_dir)
        return cfg


def _load_yaml(config_path: str | Path | None) -> dict:
    """Read a YAML config file and return its contents as a dict."""
    if config_path is not None:
        path = Path(config_path)
    else:
        path = Path("wireghost.yml")

    if not path.is_file():
        return {}

    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return data if isinstance(data, dict) else {}
    except (yaml.YAMLError, OSError):
        return {}


def _apply_yaml(cfg: ScanConfig, data: dict) -> None:
    """Apply values from a parsed YAML dict onto *cfg*."""
    _YAML_MAP: dict[str, str] = {
        "target": "target",
        "output_dir": "output_dir",
        "parallelism": "parallelism",
        "version_detect": "version_detect",
        "os_detect": "os_detect",
        "service_enum": "service_enum",
        "skip_nuclei": "skip_nuclei",
        "skip_vuln": "skip_vuln",
        "tool_timeout": "tool_timeout",
        "nmap_timeout": "nmap_timeout",
        "report_formats": "report_formats",
        "report_title": "report_title",
        "verbose": "verbose",
        "logo_path": "logo_path",
        "nuclei_templates": "nuclei_templates",
        "nuclei_default_templates": "nuclei_default_templates",
        "nuclei_batch_size": "nuclei_batch_size",
        "scan_unresponsive": "scan_unresponsive",
        "skip_screenshots": "skip_screenshots",
        "skip_enum4linux": "skip_enum4linux",
        "skip_nikto": "skip_nikto",
        "skip_netexec": "skip_netexec",
        "skip_arp_scan": "skip_arp_scan",
        "skip_tls_audit": "skip_tls_audit",
        "skip_snmp_enum": "skip_snmp_enum",
        "skip_nfs_enum": "skip_nfs_enum",
        "skip_ldap_enum": "skip_ldap_enum",
        "skip_web_crawl": "skip_web_crawl",
        "skip_msf_scan": "skip_msf_scan",
        "skip_brute_force": "skip_brute_force",
        "msf_metadata_path": "msf_metadata_path",
    }
    for yaml_key, attr in _YAML_MAP.items():
        if yaml_key in data:
            value = data[yaml_key]
            if attr in ("output_dir", "logo_path"):
                value = Path(str(value))
            setattr(cfg, attr, value)


def _apply_env(cfg: ScanConfig) -> None:
    """Override config values from WIREGHOST_* environment variables."""
    _ENV_MAP: dict[str, tuple[str, type]] = {
        "WIREGHOST_TARGET": ("target", str),
        "WIREGHOST_OUTPUT_DIR": ("output_dir", Path),
        "WIREGHOST_PARALLELISM": ("parallelism", int),
        "WIREGHOST_VERSION_DETECT": ("version_detect", bool),
        "WIREGHOST_OS_DETECT": ("os_detect", bool),
        "WIREGHOST_SERVICE_ENUM": ("service_enum", bool),
        "WIREGHOST_SKIP_NUCLEI": ("skip_nuclei", bool),
        "WIREGHOST_SKIP_VULN": ("skip_vuln", bool),
        "WIREGHOST_TOOL_TIMEOUT": ("tool_timeout", float),
        "WIREGHOST_NMAP_TIMEOUT": ("nmap_timeout", float),
        "WIREGHOST_REPORT_TITLE": ("report_title", str),
        "WIREGHOST_VERBOSE": ("verbose", bool),
        "WIREGHOST_LOGO": ("logo_path", Path),
        "WIREGHOST_NUCLEI_TEMPLATES": ("nuclei_templates", str),
        "WIREGHOST_NUCLEI_DEFAULT_TEMPLATES": ("nuclei_default_templates", bool),
        "WIREGHOST_NUCLEI_BATCH_SIZE": ("nuclei_batch_size", int),
        "WIREGHOST_SCAN_UNRESPONSIVE": ("scan_unresponsive", bool),
        "WIREGHOST_SKIP_SCREENSHOTS": ("skip_screenshots", bool),
        "WIREGHOST_SKIP_ENUM4LINUX": ("skip_enum4linux", bool),
        "WIREGHOST_SKIP_NIKTO": ("skip_nikto", bool),
        "WIREGHOST_SKIP_NETEXEC": ("skip_netexec", bool),
        "WIREGHOST_SKIP_ARP_SCAN": ("skip_arp_scan", bool),
        "WIREGHOST_SKIP_TLS_AUDIT": ("skip_tls_audit", bool),
        "WIREGHOST_SKIP_SNMP_ENUM": ("skip_snmp_enum", bool),
        "WIREGHOST_SKIP_NFS_ENUM": ("skip_nfs_enum", bool),
        "WIREGHOST_SKIP_LDAP_ENUM": ("skip_ldap_enum", bool),
        "WIREGHOST_SKIP_WEB_CRAWL": ("skip_web_crawl", bool),
        "WIREGHOST_SKIP_MSF_SCAN": ("skip_msf_scan", bool),
        "WIREGHOST_SKIP_BRUTE_FORCE": ("skip_brute_force", bool),
        "WIREGHOST_MSF_METADATA_PATH": ("msf_metadata_path", str),
    }
    for env_var, (attr, conv) in _ENV_MAP.items():
        raw = os.environ.get(env_var)
        if raw is None:
            continue
        if conv is bool:
            value: object = raw.lower() in ("1", "true", "yes")
        elif conv is Path:
            value = Path(raw)
        else:
            try:
                value = conv(raw)
            except (ValueError, TypeError):
                continue
        setattr(cfg, attr, value)
