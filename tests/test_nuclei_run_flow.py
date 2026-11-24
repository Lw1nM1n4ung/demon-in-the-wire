"""Tests for nuclei run flow: stale output, failed runs, duplicates."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wireghost.models.scan import Host, Port, Service
from wireghost.pipeline import vulnscan


class _Result:
    def __init__(self, returncode=0):
        self.returncode = returncode
        self.stdout = ""
        self.stderr = ""


class _Tree:
    def __init__(self, tmp: Path):
        self.tmp = tmp

    def host_vuln_dir(self, ip):
        d = self.tmp / ip / "vuln"
        d.mkdir(parents=True, exist_ok=True)
        return d


class _Config:
    tool_timeout = 30
    nuclei_templates = ""
    nuclei_default_templates = True


def _host() -> Host:
    return Host(
        ip="10.0.0.1",
        ports=[Port(number=80, service=Service(name="http"))],
        web_endpoints=["http://10.0.0.1:80"],
    )


def _line(tid="tmpl", matched="http://10.0.0.1:80/x"):
    return json.dumps(
        {
            "template-id": tid,
            "info": {"name": "T", "severity": "high", "description": "d", "tags": []},
            "matched-at": matched,
            "host": "10.0.0.1",
            "matcher-name": "m",
        }
    )


@pytest.mark.asyncio
async def test_stale_nuclei_output_is_removed_before_run(tmp_path, monkeypatch):
    """A previous scan's file must not be attributed to this run."""
    tree = _Tree(tmp_path)
    vuln = tree.host_vuln_dir("10.0.0.1")
    (vuln / "nuclei.json").write_text(_line(tid="OLD") + "\n", encoding="utf-8")

    async def fake_run_tool(cmd, **kwargs):
        # nuclei failed and wrote nothing
        return _Result(returncode=-9)

    monkeypatch.setattr(vulnscan, "run_tool", fake_run_tool)
    monkeypatch.setattr(vulnscan, "_collect_template_dirs", lambda _cfg: [])

    findings = await vulnscan.run_nuclei(_host(), _Config(), tree)
    assert findings == [], "stale findings from a previous run leaked through"


@pytest.mark.asyncio
async def test_duplicate_matches_are_collapsed(tmp_path, monkeypatch):
    tree = _Tree(tmp_path)

    async def fake_run_tool(cmd, **kwargs):
        out = Path(cmd[cmd.index("-o") + 1])
        out.write_text("\n".join([_line(), _line(), _line(tid="other")]) + "\n", encoding="utf-8")
        return _Result()

    monkeypatch.setattr(vulnscan, "run_tool", fake_run_tool)
    monkeypatch.setattr(vulnscan, "_collect_template_dirs", lambda _cfg: [])

    findings = await vulnscan.run_nuclei(_host(), _Config(), tree)
    assert len(findings) == 2, "duplicate nuclei matches were not collapsed"
