"""Tests for wireghost.parsers.enum4linux."""

from __future__ import annotations

from pathlib import Path

from wireghost.models.severity import Severity
from wireghost.parsers.enum4linux import parse_enum4linux_output

FIXTURE_DIR = Path(__file__).parent / "fixtures"


class TestParseEnum4linuxOutput:
    def test_parses_null_session(self):
        output = (FIXTURE_DIR / "enum4linux_output.txt").read_text()
        findings = parse_enum4linux_output(output, host_ip="10.0.0.1")
        null_sess = [f for f in findings if "Null Session" in f.title]
        assert len(null_sess) == 1
        assert null_sess[0].severity == Severity.HIGH
        assert null_sess[0].source == "enum4linux"

    def test_parses_os_info(self):
        output = (FIXTURE_DIR / "enum4linux_output.txt").read_text()
        findings = parse_enum4linux_output(output, host_ip="10.0.0.1")
        os_findings = [f for f in findings if "OS Detection" in f.title]
        assert len(os_findings) == 1
        assert "Windows 10 Pro 19045" in os_findings[0].title
        assert os_findings[0].severity == Severity.INFO

    def test_parses_users(self):
        output = (FIXTURE_DIR / "enum4linux_output.txt").read_text()
        findings = parse_enum4linux_output(output, host_ip="10.0.0.1")
        user_findings = [f for f in findings if "User Enumeration" in f.title]
        assert len(user_findings) == 1
        assert "3 user(s)" in user_findings[0].title
        assert "Administrator" in user_findings[0].description
        assert "svc_backup" in user_findings[0].description

    def test_parses_shares(self):
        output = (FIXTURE_DIR / "enum4linux_output.txt").read_text()
        findings = parse_enum4linux_output(output, host_ip="10.0.0.1")
        share_findings = [f for f in findings if "Share Enumeration" in f.title]
        assert len(share_findings) == 1
        assert share_findings[0].severity in (Severity.LOW, Severity.MEDIUM)

    def test_parses_groups(self):
        output = (FIXTURE_DIR / "enum4linux_output.txt").read_text()
        findings = parse_enum4linux_output(output, host_ip="10.0.0.1")
        group_findings = [f for f in findings if "Group Enumeration" in f.title]
        assert len(group_findings) == 1
        assert "3 group(s)" in group_findings[0].title
        assert "Administrators" in group_findings[0].description

    def test_parses_password_policy(self):
        output = (FIXTURE_DIR / "enum4linux_output.txt").read_text()
        findings = parse_enum4linux_output(output, host_ip="10.0.0.1")
        policy = [f for f in findings if "Password Policy" in f.title]
        assert len(policy) == 1
        assert "Minimum password length" in policy[0].description

    def test_weak_password_policy_severity(self):
        output = (FIXTURE_DIR / "enum4linux_output.txt").read_text()
        findings = parse_enum4linux_output(output, host_ip="10.0.0.1")
        policy = [f for f in findings if "Password Policy" in f.title]
        assert policy[0].severity == Severity.MEDIUM

    def test_host_ip_set(self):
        output = (FIXTURE_DIR / "enum4linux_output.txt").read_text()
        findings = parse_enum4linux_output(output, host_ip="10.0.0.1")
        assert all(f.host == "10.0.0.1" for f in findings)

    def test_port_is_445(self):
        output = (FIXTURE_DIR / "enum4linux_output.txt").read_text()
        findings = parse_enum4linux_output(output, host_ip="10.0.0.1")
        assert all(f.port == "445" for f in findings)

    def test_all_sources_enum4linux(self):
        output = (FIXTURE_DIR / "enum4linux_output.txt").read_text()
        findings = parse_enum4linux_output(output, host_ip="10.0.0.1")
        assert all(f.source == "enum4linux" for f in findings)

    def test_empty_string_returns_empty(self):
        assert parse_enum4linux_output("") == []

    def test_none_input_returns_empty(self):
        assert parse_enum4linux_output("") == []

    def test_whitespace_only_returns_empty(self):
        assert parse_enum4linux_output("   \n\n  ") == []

    def test_access_denied_no_null_session(self):
        output = (
            "[*] Attempting to make a null session on 10.0.0.1...\n"
            "[E] Couldn't establish null session\n"
        )
        findings = parse_enum4linux_output(output, host_ip="10.0.0.1")
        null_sess = [f for f in findings if "Null Session" in f.title]
        assert len(null_sess) == 0

    def test_partial_output_only_users(self):
        output = "user:[testuser] rid:[0x3e8]\nuser:[admin] rid:[0x1f4]\n"
        findings = parse_enum4linux_output(output, host_ip="10.0.0.1")
        user_findings = [f for f in findings if "User Enumeration" in f.title]
        assert len(user_findings) == 1
        assert "2 user(s)" in user_findings[0].title

    def test_no_findings_from_garbage(self):
        findings = parse_enum4linux_output("random garbage text\nno patterns here\n")
        assert findings == []

    def test_default_host_ip_empty(self):
        output = "user:[testuser] rid:[0x3e8]\n"
        findings = parse_enum4linux_output(output)
        assert findings[0].host == ""

    def test_tags_present(self):
        output = (FIXTURE_DIR / "enum4linux_output.txt").read_text()
        findings = parse_enum4linux_output(output, host_ip="10.0.0.1")
        for f in findings:
            assert len(f.tags) > 0
            assert "smb" in f.tags
