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
    skip_nuclei: bool = False
    skip_vuln: bool = False
    tool_timeout: float = 3600.0
    report_formats: list[str] = field(
        default_factory=lambda: ["html", "docx", "xlsx"]
    )
    report_title: str = "Security Assessment Summary Report"
    verbose: bool = False
    logo_path: Path | None = None

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
        "skip_nuclei": "skip_nuclei",
        "skip_vuln": "skip_vuln",
        "tool_timeout": "tool_timeout",
        "report_formats": "report_formats",
        "report_title": "report_title",
        "verbose": "verbose",
        "logo_path": "logo_path",
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
        "WIREGHOST_SKIP_NUCLEI": ("skip_nuclei", bool),
        "WIREGHOST_SKIP_VULN": ("skip_vuln", bool),
        "WIREGHOST_TOOL_TIMEOUT": ("tool_timeout", float),
        "WIREGHOST_REPORT_TITLE": ("report_title", str),
        "WIREGHOST_VERBOSE": ("verbose", bool),
        "WIREGHOST_LOGO": ("logo_path", Path),
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
