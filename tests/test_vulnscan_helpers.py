"""Tests for vulnscan pure helper functions — template collection, script building, version extraction."""

from __future__ import annotations

from pathlib import Path

from wireghost.models.scan import Host, Port, Service, WebTech
from wireghost.pipeline.vulnscan import (
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


class TestCollectTemplateDirs:
    def test_no_templates_returns_empty(self):
        cfg = _FakeConfig(nuclei_templates="")
        assert _collect_template_dirs(cfg) == []

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
        ports=[
            Port(number=n, service=Service(name=s) if s else None)
            for n, s in services
        ],
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
                        name="ssh", product="OpenSSH",
                        version="9.6p1 Ubuntu 3ubuntu13.15",
                    ),
                ),
            ],
        )
        terms = _collect_versions(h)
        assert terms[0][0] == "OpenSSH 9.6"
