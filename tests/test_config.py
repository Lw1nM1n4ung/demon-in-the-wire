"""Tests for wireghost.config — layered ScanConfig loader."""

from __future__ import annotations

from pathlib import Path

from wireghost.config import ScanConfig


class TestScanConfigDefaults:
    def test_default_target_empty(self):
        cfg = ScanConfig()
        assert cfg.target == ""

    def test_default_parallelism(self):
        cfg = ScanConfig()
        assert cfg.parallelism == 10

    def test_default_output_dir(self):
        cfg = ScanConfig()
        assert cfg.output_dir == Path("./output")

    def test_default_report_formats(self):
        cfg = ScanConfig()
        assert cfg.report_formats == ["html", "docx", "xlsx"]

    def test_default_nuclei_batch_size(self):
        cfg = ScanConfig()
        assert cfg.nuclei_batch_size == 5000

    def test_default_tool_timeout(self):
        cfg = ScanConfig()
        assert cfg.tool_timeout == 3600.0

    def test_default_nmap_timeout(self):
        cfg = ScanConfig()
        assert cfg.nmap_timeout == 5400.0

    def test_default_skip_flags_false(self):
        cfg = ScanConfig()
        assert cfg.skip_nuclei is False
        assert cfg.skip_vuln is False
        assert cfg.skip_enum4linux is False
        assert cfg.skip_nikto is False
        assert cfg.skip_netexec is False
        assert cfg.skip_screenshots is False

    def test_default_skip_msf_scan_false(self):
        cfg = ScanConfig()
        assert cfg.skip_msf_scan is False

    def test_default_msf_metadata_path(self):
        cfg = ScanConfig()
        assert cfg.msf_metadata_path == "/opt/msf/modules_metadata_base.json"


class TestScanConfigYaml:
    def test_yaml_override(self, tmp_path):
        yml = tmp_path / "wireghost.yml"
        yml.write_text("parallelism: 20\nskip_nuclei: true\n")
        cfg = ScanConfig.load(config_path=yml)
        assert cfg.parallelism == 20
        assert cfg.skip_nuclei is True

    def test_yaml_target(self, tmp_path):
        yml = tmp_path / "wireghost.yml"
        yml.write_text("target: 192.168.1.0/24\n")
        cfg = ScanConfig.load(config_path=yml)
        assert cfg.target == "192.168.1.0/24"

    def test_yaml_report_formats(self, tmp_path):
        yml = tmp_path / "wireghost.yml"
        yml.write_text("report_formats:\n  - dashboard\n  - docx\n")
        cfg = ScanConfig.load(config_path=yml)
        assert cfg.report_formats == ["dashboard", "docx"]

    def test_yaml_output_dir_as_path(self, tmp_path):
        yml = tmp_path / "wireghost.yml"
        yml.write_text("output_dir: /tmp/scans\n")
        cfg = ScanConfig.load(config_path=yml)
        assert cfg.output_dir == Path("/tmp/scans")

    def test_missing_yaml_uses_defaults(self, tmp_path):
        cfg = ScanConfig.load(config_path=tmp_path / "nonexistent.yml")
        assert cfg.parallelism == 10

    def test_malformed_yaml_uses_defaults(self, tmp_path):
        yml = tmp_path / "wireghost.yml"
        yml.write_text(": : : not valid yaml ][")
        cfg = ScanConfig.load(config_path=yml)
        assert cfg.parallelism == 10

    def test_yaml_nuclei_batch_size(self, tmp_path):
        yml = tmp_path / "wireghost.yml"
        yml.write_text("nuclei_batch_size: 2000\n")
        cfg = ScanConfig.load(config_path=yml)
        assert cfg.nuclei_batch_size == 2000


class TestScanConfigEnv:
    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("WIREGHOST_PARALLELISM", "50")
        cfg = ScanConfig.load()
        assert cfg.parallelism == 50

    def test_env_bool_true(self, monkeypatch):
        monkeypatch.setenv("WIREGHOST_SKIP_NUCLEI", "true")
        cfg = ScanConfig.load()
        assert cfg.skip_nuclei is True

    def test_env_bool_yes(self, monkeypatch):
        monkeypatch.setenv("WIREGHOST_VERBOSE", "yes")
        cfg = ScanConfig.load()
        assert cfg.verbose is True

    def test_env_bool_one(self, monkeypatch):
        monkeypatch.setenv("WIREGHOST_SKIP_VULN", "1")
        cfg = ScanConfig.load()
        assert cfg.skip_vuln is True

    def test_env_bool_false(self, monkeypatch):
        monkeypatch.setenv("WIREGHOST_SKIP_NUCLEI", "false")
        cfg = ScanConfig.load()
        assert cfg.skip_nuclei is False

    def test_env_target(self, monkeypatch):
        monkeypatch.setenv("WIREGHOST_TARGET", "10.0.0.0/8")
        cfg = ScanConfig.load()
        assert cfg.target == "10.0.0.0/8"

    def test_env_output_dir(self, monkeypatch):
        monkeypatch.setenv("WIREGHOST_OUTPUT_DIR", "/var/scans")
        cfg = ScanConfig.load()
        assert cfg.output_dir == Path("/var/scans")

    def test_env_invalid_int_ignored(self, monkeypatch):
        monkeypatch.setenv("WIREGHOST_PARALLELISM", "not_a_number")
        cfg = ScanConfig.load()
        assert cfg.parallelism == 10

    def test_env_skip_msf_scan(self, monkeypatch):
        monkeypatch.setenv("WIREGHOST_SKIP_MSF_SCAN", "true")
        cfg = ScanConfig.load()
        assert cfg.skip_msf_scan is True

    def test_env_msf_metadata_path(self, monkeypatch):
        monkeypatch.setenv("WIREGHOST_MSF_METADATA_PATH", "/custom/path.json")
        cfg = ScanConfig.load()
        assert cfg.msf_metadata_path == "/custom/path.json"


class TestScanConfigOverrides:
    def test_explicit_override(self):
        cfg = ScanConfig.load(target="10.0.0.1", parallelism=30)
        assert cfg.target == "10.0.0.1"
        assert cfg.parallelism == 30

    def test_none_override_ignored(self):
        cfg = ScanConfig.load(parallelism=None)
        assert cfg.parallelism == 10

    def test_override_output_dir_from_string(self):
        cfg = ScanConfig.load(output_dir="/tmp/test")
        assert cfg.output_dir == Path("/tmp/test")

    def test_skip_flags(self):
        cfg = ScanConfig.load(skip_netexec=True, skip_nikto=True)
        assert cfg.skip_netexec is True
        assert cfg.skip_nikto is True


class TestScanConfigPriority:
    def test_explicit_beats_env(self, monkeypatch):
        monkeypatch.setenv("WIREGHOST_PARALLELISM", "50")
        cfg = ScanConfig.load(parallelism=5)
        assert cfg.parallelism == 5

    def test_env_beats_yaml(self, monkeypatch, tmp_path):
        yml = tmp_path / "wireghost.yml"
        yml.write_text("parallelism: 20\n")
        monkeypatch.setenv("WIREGHOST_PARALLELISM", "50")
        cfg = ScanConfig.load(config_path=yml)
        assert cfg.parallelism == 50

    def test_explicit_beats_yaml(self, tmp_path):
        yml = tmp_path / "wireghost.yml"
        yml.write_text("parallelism: 20\n")
        cfg = ScanConfig.load(config_path=yml, parallelism=5)
        assert cfg.parallelism == 5

    def test_full_priority_chain(self, monkeypatch, tmp_path):
        yml = tmp_path / "wireghost.yml"
        yml.write_text("parallelism: 20\nreport_title: yaml-title\n")
        monkeypatch.setenv("WIREGHOST_PARALLELISM", "50")
        cfg = ScanConfig.load(config_path=yml, parallelism=5)
        assert cfg.parallelism == 5
        assert cfg.report_title == "yaml-title"
