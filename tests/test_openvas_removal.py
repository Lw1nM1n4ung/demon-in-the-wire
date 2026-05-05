"""Regression tests — verify OpenVAS is fully removed from the codebase."""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestOpenvasRemoval:
    def test_no_openvas_parser(self):
        assert not (ROOT / "src" / "wireghost" / "parsers" / "openvas.py").exists()

    def test_no_openvas_fixture(self):
        assert not (ROOT / "tests" / "fixtures" / "openvas_report.xml").exists()

    def test_no_openvas_import_in_source(self):
        result = subprocess.run(
            ["grep", "-rn", "import.*openvas", str(ROOT / "src")],
            capture_output=True, text=True,
        )
        assert result.stdout.strip() == "", f"Found openvas imports:\n{result.stdout}"

    def test_no_skip_openvas_in_config(self):
        config_py = (ROOT / "src" / "wireghost" / "config.py").read_text()
        assert "skip_openvas" not in config_py

    def test_no_scannerctl_in_source(self):
        result = subprocess.run(
            ["grep", "-rn", "scannerctl", str(ROOT / "src")],
            capture_output=True, text=True,
        )
        assert result.stdout.strip() == "", f"Found scannerctl references:\n{result.stdout}"

    def test_no_greenbone_in_source(self):
        result = subprocess.run(
            ["grep", "-rn", "greenbone", str(ROOT / "src")],
            capture_output=True, text=True,
        )
        assert result.stdout.strip() == "", f"Found greenbone references:\n{result.stdout}"

    def test_no_openvas_in_pipeline(self):
        result = subprocess.run(
            ["grep", "-rn", "openvas", str(ROOT / "src" / "wireghost" / "pipeline")],
            capture_output=True, text=True,
        )
        assert result.stdout.strip() == "", f"Found openvas in pipeline:\n{result.stdout}"

    def test_dockerfile_two_stages(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        from_count = sum(1 for line in dockerfile.splitlines() if line.strip().startswith("FROM "))
        assert from_count == 2, f"Expected 2 FROM stages, got {from_count}"

    def test_no_openvas_in_tools_health(self):
        tools_health = (ROOT / "web_portal" / "scanner" / "tools_health.py").read_text()
        assert "scannerctl" not in tools_health
        assert "openvas" not in tools_health.lower()

    def test_no_openvas_in_views(self):
        views = (ROOT / "web_portal" / "scanner" / "views.py").read_text()
        assert "skip_openvas" not in views

    def test_no_openvas_in_setup_wizard_ui(self):
        setup_boot = (ROOT / "web" / "js" / "public" / "setup-boot.js").read_text()
        assert "openvas" not in setup_boot.lower()

    def test_no_openvas_in_settings_ui(self):
        settings_js = (ROOT / "web" / "js" / "app" / "pages" / "settings.js").read_text()
        assert "openvas" not in settings_js.lower()

    def test_no_openvas_in_updater(self):
        updater = (ROOT / "src" / "wireghost" / "utils" / "updater.py").read_text()
        assert "openvas" not in updater.lower()
        assert "greenbone" not in updater.lower()
        assert "scannerctl" not in updater.lower()

    def test_no_openvas_in_test_imports(self):
        test_parsers = (ROOT / "tests" / "test_parsers.py").read_text()
        assert "openvas" not in test_parsers.lower()
