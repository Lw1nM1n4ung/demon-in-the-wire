"""Tests for vulnscan pure helper functions — template collection, script building, version extraction."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from wireghost.models.scan import Host, Port, Service, WebTech
from wireghost.pipeline import vulnscan
from wireghost.pipeline.vulnscan import (
    _build_nuclei_targets,
    _build_script_arg,
    _collect_template_dirs,
    _collect_versions,
    _glob_templates,
    _SERVICE_SCRIPTS,
)


# ================================================================
# _collect_template_dirs
# ================================================================


class _FakeConfig:
    """Minimal config stub for template dir tests."""

    def __init__(self, nuclei_templates="", nuclei_default_templates=True):
        self.nuclei_templates = nuclei_templates
        self.nuclei_default_templates = nuclei_default_templates
        self.tool_timeout = 3600


class TestBuildNucleiTargets:
    def test_all_open_tcp_ports_become_targets(self):
        host = Host(
            ip="10.0.0.5",
            ports=[
                Port(number=80, service=Service(name="http")),
                Port(number=443, service=Service(name="https")),
                Port(number=22, service=Service(name="ssh")),
                Port(number=3306, service=Service(name="mysql")),
                Port(number=3389),
            ],
        )
        targets = _build_nuclei_targets(host)
        assert targets == [
            "http://10.0.0.5:80",
            "https://10.0.0.5:443",
            "10.0.0.5:22",
            "10.0.0.5:3306",
            "10.0.0.5:3389",
        ]

    def test_non_web_ports_use_host_port_form(self):
        host = Host(ip="10.0.0.5", ports=[Port(number=22, service=Service(name="ssh"))])
        assert _build_nuclei_targets(host) == ["10.0.0.5:22"]

    def test_http_alt_service_maps_to_http_scheme(self):
        host = Host(ip="10.0.0.5", ports=[Port(number=8080, service=Service(name="http-proxy"))])
        assert _build_nuclei_targets(host) == ["http://10.0.0.5:8080"]

    def test_https_alt_service_maps_to_https_scheme(self):
        host = Host(ip="10.0.0.5", ports=[Port(number=8443, service=Service(name="https-alt"))])
        assert _build_nuclei_targets(host) == ["https://10.0.0.5:8443"]

    def test_web_endpoints_kept_and_deduplicated_against_ports(self):
        host = Host(
            ip="10.0.0.5",
            web_endpoints=["http://10.0.0.5", "https://10.0.0.5:8443"],
            ports=[
                Port(number=80, service=Service(name="http")),
                Port(number=8443, service=Service(name="https-alt")),
                Port(number=22, service=Service(name="ssh")),
            ],
        )
        assert _build_nuclei_targets(host) == [
            "http://10.0.0.5",
            "https://10.0.0.5:8443",
            "10.0.0.5:22",
        ]

    def test_no_ports_or_endpoints_returns_empty(self):
        assert _build_nuclei_targets(Host(ip="10.0.0.5")) == []

    def test_udp_ports_skipped(self):
        host = Host(
            ip="10.0.0.5",
            ports=[Port(number=161, protocol="udp", service=Service(name="snmp"))],
        )
        assert _build_nuclei_targets(host) == []


class TestCollectTemplateDirs:
    def test_no_templates_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr(vulnscan, "BUNDLED_NUCLEI_TEMPLATES", tmp_path / "missing")
        cfg = _FakeConfig(nuclei_templates="")
        assert _collect_template_dirs(cfg) == []

    def test_bundled_dir_used_when_no_explicit_templates(self, tmp_path, monkeypatch):
        bundled = tmp_path / "bundled"
        bundled.mkdir()
        monkeypatch.setattr(vulnscan, "BUNDLED_NUCLEI_TEMPLATES", bundled)
        cfg = _FakeConfig(nuclei_templates="")
        assert _collect_template_dirs(cfg) == [bundled]

    def test_custom_dir_only(self, tmp_path: Path):
        custom = tmp_path / "custom_templates"
        custom.mkdir()
        cfg = _FakeConfig(nuclei_templates=str(custom), nuclei_default_templates=False)
        dirs = _collect_template_dirs(cfg)
        assert len(dirs) == 1
        assert dirs[0] == custom

    def test_custom_plus_default(self, tmp_path: Path, monkeypatch):
        custom = tmp_path / "custom"
        custom.mkdir()
        default = tmp_path / "nuclei-templates"
        default.mkdir()
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        cfg = _FakeConfig(nuclei_templates=str(custom), nuclei_default_templates=True)
        dirs = _collect_template_dirs(cfg)
        assert len(dirs) == 2

    def test_default_dir_missing_excluded(self, tmp_path: Path, monkeypatch):
        custom = tmp_path / "custom"
        custom.mkdir()
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        cfg = _FakeConfig(nuclei_templates=str(custom), nuclei_default_templates=True)
        dirs = _collect_template_dirs(cfg)
        assert len(dirs) == 1


# ================================================================
# _glob_templates
# ================================================================


class TestGlobTemplates:
    def test_finds_yaml_files(self, tmp_path: Path):
        d = tmp_path / "templates"
        d.mkdir()
        (d / "a.yaml").write_text("id: a")
        (d / "b.yaml").write_text("id: b")
        (d / "readme.md").write_text("not a template")
        result = _glob_templates([d])
        assert len(result) == 2
        assert all(r.endswith(".yaml") for r in result)

    def test_recursive(self, tmp_path: Path):
        d = tmp_path / "templates"
        sub = d / "cves" / "2024"
        sub.mkdir(parents=True)
        (sub / "CVE-2024-1234.yaml").write_text("id: x")
        result = _glob_templates([d])
        assert len(result) == 1

    def test_empty_dir(self, tmp_path: Path):
        d = tmp_path / "empty"
        d.mkdir()
        assert _glob_templates([d]) == []

    def test_dedup_across_dirs(self, tmp_path: Path):
        d1 = tmp_path / "dir1"
        d2 = tmp_path / "dir2"
        d1.mkdir()
        d2.mkdir()
        (d1 / "a.yaml").write_text("id: a")
        (d2 / "b.yaml").write_text("id: b")
        result = _glob_templates([d1, d2])
        assert len(result) == 2

    def test_sorted_output(self, tmp_path: Path):
        d = tmp_path / "templates"
        d.mkdir()
        (d / "z.yaml").write_text("id: z")
        (d / "a.yaml").write_text("id: a")
        result = _glob_templates([d])
        assert result == sorted(result)


# ================================================================
# _build_script_arg
# ================================================================


def _host_with_services(services: list[tuple[int, str]]) -> Host:
    return Host(
        ip="10.0.0.1",
        ports=[Port(number=n, service=Service(name=s) if s else None) for n, s in services],
    )


class TestBuildScriptArg:
    def test_no_ports(self):
        h = Host(ip="10.0.0.1")
        result = _build_script_arg(h)
        assert result == "vuln,default"

    def test_ssh_adds_scripts(self):
        h = _host_with_services([(22, "ssh")])
        result = _build_script_arg(h)
        assert "ssh-auth-methods" in result
        assert "ssh2-enum-algos" in result
        assert result.startswith("vuln,default,")

    def test_http_adds_scripts(self):
        h = _host_with_services([(80, "http")])
        result = _build_script_arg(h)
        assert "http-enum" in result
        assert "http-methods" in result

    def test_mysql_adds_scripts(self):
        h = _host_with_services([(3306, "mysql")])
        result = _build_script_arg(h)
        assert "mysql-info" in result

    def test_multiple_services_combined(self):
        h = _host_with_services([(22, "ssh"), (80, "http")])
        result = _build_script_arg(h)
        assert "ssh-auth-methods" in result
        assert "http-enum" in result

    def test_unknown_service_no_extra(self):
        h = _host_with_services([(9999, "custom-app")])
        result = _build_script_arg(h)
        assert result == "vuln,default"

    def test_scripts_sorted(self):
        h = _host_with_services([(22, "ssh"), (80, "http"), (3306, "mysql")])
        result = _build_script_arg(h)
        parts = result.split(",")
        extra = parts[2:]
        assert extra == sorted(extra)

    def test_service_scripts_map_coverage(self):
        assert "ssh" in _SERVICE_SCRIPTS
        assert "http" in _SERVICE_SCRIPTS
        assert "mysql" in _SERVICE_SCRIPTS
        assert "ftp" in _SERVICE_SCRIPTS
        assert "redis" in _SERVICE_SCRIPTS
        assert "smtp" in _SERVICE_SCRIPTS


# ================================================================
# _collect_versions
# ================================================================


class TestCollectVersions:
    def test_service_with_version(self):
        h = Host(
            ip="10.0.0.1",
            ports=[
                Port(
                    number=22,
                    service=Service(name="ssh", product="OpenSSH", version="9.6p1"),
                ),
            ],
        )
        terms = _collect_versions(h)
        assert len(terms) == 1
        assert terms[0] == ("OpenSSH 9.6", "22")

    def test_no_version_excluded(self):
        h = Host(
            ip="10.0.0.1",
            ports=[
                Port(number=80, service=Service(name="http", product="nginx")),
            ],
        )
        terms = _collect_versions(h)
        assert terms == []

    def test_skip_generic_products(self):
        h = Host(
            ip="10.0.0.1",
            ports=[
                Port(
                    number=80,
                    service=Service(name="http", product="http", version="1.1"),
                ),
            ],
        )
        terms = _collect_versions(h)
        assert terms == []

    def test_dedup_same_product_version(self):
        h = Host(
            ip="10.0.0.1",
            ports=[
                Port(number=22, service=Service(name="ssh", product="OpenSSH", version="9.6")),
                Port(number=2222, service=Service(name="ssh", product="OpenSSH", version="9.6")),
            ],
        )
        terms = _collect_versions(h)
        assert len(terms) == 1

    def test_technology_with_version(self):
        h = Host(ip="10.0.0.1")
        h.technologies.append(WebTech(name="jQuery", version="3.6.0", url="http://10.0.0.1:80"))
        terms = _collect_versions(h)
        assert len(terms) == 1
        assert terms[0][0] == "jQuery 3.6.0"

    def test_technology_without_version_excluded(self):
        h = Host(ip="10.0.0.1")
        h.technologies.append(WebTech(name="nginx", version="", url=""))
        terms = _collect_versions(h)
        assert terms == []

    def test_mixed_ports_and_techs(self):
        h = Host(
            ip="10.0.0.1",
            ports=[
                Port(number=22, service=Service(name="ssh", product="OpenSSH", version="9.6")),
            ],
        )
        h.technologies.append(WebTech(name="Apache", version="2.4.58", url="http://10.0.0.1:80"))
        terms = _collect_versions(h)
        assert len(terms) == 2

    def test_sorted_output(self):
        h = Host(
            ip="10.0.0.1",
            ports=[
                Port(number=80, service=Service(name="http", product="nginx", version="1.24")),
                Port(number=22, service=Service(name="ssh", product="OpenSSH", version="9.6")),
            ],
        )
        terms = _collect_versions(h)
        keys = [t[0] for t in terms]
        assert keys == sorted(keys)

    def test_version_extracts_major_minor(self):
        h = Host(
            ip="10.0.0.1",
            ports=[
                Port(
                    number=22,
                    service=Service(
                        name="ssh",
                        product="OpenSSH",
                        version="9.6p1 Ubuntu 3ubuntu13.15",
                    ),
                ),
            ],
        )
        terms = _collect_versions(h)
        assert terms[0][0] == "OpenSSH 9.6"


class TestRunNucleiCommand:
    @patch("wireghost.pipeline.vulnscan.run_tool", new_callable=AsyncMock)
    async def test_single_run_without_batching_or_concurrency_flags(self, mock_run, tmp_path):
        class Tree:
            def host_vuln_dir(self, ip):
                return tmp_path

        mock_run.return_value = MagicMock(returncode=0)
        host = Host(ip="10.0.0.1", ports=[Port(number=22, service=Service(name="ssh"))])
        cfg = _FakeConfig(nuclei_templates=str(tmp_path), nuclei_default_templates=False)

        await vulnscan.run_nuclei(host, cfg, Tree())

        assert mock_run.await_count == 1, "nuclei must run once per host — no template batching"
        cmd = mock_run.call_args.args[0]
        assert "-c" not in cmd, "internal nuclei concurrency flag must be removed"
        assert "-rl" not in cmd, "nuclei rate-limit flag must be removed"
        assert "-timeout" not in cmd, "explicit nuclei request timeout must be removed"
        assert cmd.count("-t") == 1
