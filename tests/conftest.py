"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURE_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture()
def nmap_port_scan_xml() -> Path:
    return FIXTURE_DIR / "nmap_port_scan.xml"


@pytest.fixture()
def nmap_vuln_scan_xml() -> Path:
    return FIXTURE_DIR / "nmap_vuln_scan.xml"


@pytest.fixture()
def nuclei_array_json() -> Path:
    return FIXTURE_DIR / "nuclei_array.json"


@pytest.fixture()
def nuclei_jsonl_json() -> Path:
    return FIXTURE_DIR / "nuclei_jsonl.json"
