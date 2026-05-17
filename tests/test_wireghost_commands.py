"""Comprehensive tests for CLI command coverage gaps.

Covers: write ops (create/update/delete/clone/toggle), reports, notifications,
system remaining commands, dashboard screenshots, findings/hosts/exploits detail,
error handling, and dispatcher.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest
from typer.testing import CliRunner

from wireghost.cli.scans import app as scans_app
from wireghost.cli.policies import app as policies_app
from wireghost.cli.schedules import app as schedules_app
from wireghost.cli.users import app as users_app
from wireghost.cli.tokens import app as tokens_app
from wireghost.cli.sessions import app as sessions_app
from wireghost.cli.findings import app as findings_app
from wireghost.cli.exploits import app as exploits_app
from wireghost.cli.hosts import app as hosts_app
from wireghost.cli.reports import app as reports_app
from wireghost.cli.notifications import app as notifications_app
from wireghost.cli.dashboard import app as dashboard_app
from wireghost.cli.system import app as system_app
from wireghost.cli import dispatcher

runner = CliRunner()


# ── Shared helpers ────────────────────────────────────────────────────────


def _mock_client(mod_path, **overrides):
    """Patch get_client in a module and return the mock client.

    Defaults: GET/POST/PATCH/PUT/DELETE all return 200 {"id": "fake-uuid"}.
    """
    mc = MagicMock()
    mc.get.return_value = _resp(200, overrides.get("get_data", {"id": "fake-uuid"}))
    mc.post.return_value = _resp(200, overrides.get("post_data", {"id": "fake-uuid"}))
    mc.patch.return_value = _resp(200, overrides.get("patch_data", {"id": "fake-uuid"}))
    mc.put.return_value = _resp(200, overrides.get("put_data", {"id": "fake-uuid"}))
    mc.delete.return_value = _resp(204, overrides.get("delete_data", {}))
    return patch(mod_path, return_value=mc), mc


def _resp(status, data=None, content=b""):
    r = MagicMock(spec=httpx.Response)
    r.status_code = status
    # Guard against bytes/str passed as data — json() must return dict/list
    if data is not None and not isinstance(data, (dict, list)):
        data = None
    r.json.return_value = data or {}
    r.content = content
    if status >= 400:
        r.raise_for_status.side_effect = httpx.HTTPStatusError(
            f"HTTP {status}", request=MagicMock(), response=r
        )
    return r


# ── Scans — write operations ──────────────────────────────────────────────


class TestScansWrite:
    def test_create_basic(self):
        p, mc = _mock_client("wireghost.cli.scans.get_client")
        with p:
            result = runner.invoke(scans_app, ["create", "10.0.0.1"])
        assert result.exit_code == 0

    def test_create_with_policy_and_title(self):
        p, mc = _mock_client("wireghost.cli.scans.get_client")
        with p:
            result = runner.invoke(scans_app, [
                "create", "10.0.0.0/24", "--policy", "full", "--title", "My Scan"
            ])
        assert result.exit_code == 0
        mc.post.assert_called_once()
        body = mc.post.call_args[1]["json"]
        assert body["target"] == "10.0.0.0/24"
        assert body["policy"] == "full"
        assert body["title"] == "My Scan"

    def test_create_error(self):
        p, mc = _mock_client("wireghost.cli.scans.get_client")
        mc.post.return_value = _resp(400, {"detail": "Bad request"})
        with p:
            result = runner.invoke(scans_app, ["create", "invalid"])
        assert result.exit_code == 1

    def test_cancel(self):
        p, mc = _mock_client("wireghost.cli.scans.get_client")
        with p:
            result = runner.invoke(scans_app, ["cancel", "deadbeef-dead-beef-dead-beefdeadbeef"])
        assert result.exit_code == 0
        mc.post.assert_called_once()

    def test_clone(self):
        p, mc = _mock_client("wireghost.cli.scans.get_client")
        with p:
            result = runner.invoke(scans_app, ["clone", "deadbeef-dead-beef-dead-beefdeadbeef"])
        assert result.exit_code == 0
        mc.post.assert_called_once()

    def test_clone_with_new_target(self):
        p, mc = _mock_client("wireghost.cli.scans.get_client")
        with p:
            result = runner.invoke(scans_app, [
                "clone", "deadbeef-dead-beef-dead-beefdeadbeef", "--target", "10.0.0.2"
            ])
        assert result.exit_code == 0
        body = mc.post.call_args[1]["json"]
        assert body["target"] == "10.0.0.2"

    def test_run(self):
        p, mc = _mock_client("wireghost.cli.scans.get_client")
        with p:
            result = runner.invoke(scans_app, ["run", "deadbeef-dead-beef-dead-beefdeadbeef"])
        assert result.exit_code == 0
        mc.post.assert_called_once()


# ── Scans — detail views ──────────────────────────────────────────────────


class TestScansDetail:
    def test_show_with_data(self):
        p, _ = _mock_client("wireghost.cli.scans.get_client", get_data={
            "id": "deadbeef-dead-beef-dead-beefdeadbeef",
            "target": "10.0.0.1",
            "status": "completed",
            "finding_count": 42,
            "host_count": 3,
        })
        with p:
            result = runner.invoke(scans_app, ["show", "deadbeef-dead-beef-dead-beefdeadbeef"])
        assert result.exit_code == 0
        assert "10.0.0.1" in result.stdout
        assert "completed" in result.stdout

    def test_show_not_found(self):
        p, mc = _mock_client("wireghost.cli.scans.get_client")
        mc.get.return_value = _resp(404, {"detail": "Not found"})
        with p:
            result = runner.invoke(scans_app, ["show", "nonexistent"])
        assert result.exit_code == 1

    def test_findings_with_filters(self):
        p, _ = _mock_client("wireghost.cli.scans.get_client", get_data=[
            {"id": "f-1", "severity": "critical", "title": "RCE found"}
        ])
        with p:
            result = runner.invoke(scans_app, [
                "findings", "deadbeef", "--severity", "critical", "--source", "nuclei"
            ])
        assert result.exit_code == 0

    def test_hosts(self):
        p, _ = _mock_client("wireghost.cli.scans.get_client", get_data=[
            {"ip": "10.0.0.1", "hostname": "web", "open_ports": 5}
        ])
        with p:
            result = runner.invoke(scans_app, ["hosts", "deadbeef"])
        assert result.exit_code == 0

    def test_topology(self):
        p, _ = _mock_client("wireghost.cli.scans.get_client", get_data={
            "nodes": [{"id": "a"}], "edges": [{"source": "a", "target": "b"}]
        })
        with p:
            result = runner.invoke(scans_app, ["topology", "deadbeef"])
        assert result.exit_code == 0


# ── Policies — full CRUD ──────────────────────────────────────────────────


class TestPoliciesWrite:
    def test_show(self):
        p, _ = _mock_client("wireghost.cli.policies.get_client", get_data={
            "id": "pol-1", "name": "Full Scan", "type": "full",
            "parallelism": 20, "timeout": 7200,
        })
        with p:
            result = runner.invoke(policies_app, ["show", "pol-1"])
        assert result.exit_code == 0
        assert "Full Scan" in result.stdout

    def test_create(self):
        p, mc = _mock_client("wireghost.cli.policies.get_client")
        with p:
            result = runner.invoke(policies_app, [
                "create", "--name", "Test Policy", "--type", "internal",
                "--parallelism", "15", "--timeout", "1800", "--skip-screenshots",
            ])
        assert result.exit_code == 0
        body = mc.post.call_args[1]["json"]
        assert body["name"] == "Test Policy"
        assert body["type"] == "internal"
        assert body["parallelism"] == 15
        assert body["skip_screenshots"] is True

    def test_update(self):
        p, mc = _mock_client("wireghost.cli.policies.get_client")
        with p:
            result = runner.invoke(policies_app, [
                "update", "pol-1", "--name", "Renamed", "--description", "Updated desc"
            ])
        assert result.exit_code == 0
        mc.patch.assert_called_once()
        body = mc.patch.call_args[1]["json"]
        assert body["name"] == "Renamed"
        assert body["description"] == "Updated desc"

    def test_delete_without_force_prompts(self):
        p, _ = _mock_client("wireghost.cli.policies.get_client")
        with p:
            result = runner.invoke(policies_app, ["delete", "pol-1"], input="n\n")
        assert result.exit_code == 0  # Exit() cancels cleanly

    def test_delete_with_force(self):
        p, mc = _mock_client("wireghost.cli.policies.get_client")
        with p:
            result = runner.invoke(policies_app, ["delete", "pol-1", "--force"])
        assert result.exit_code == 0
        mc.delete.assert_called_once()

    def test_clone(self):
        p, mc = _mock_client("wireghost.cli.policies.get_client")
        with p:
            result = runner.invoke(policies_app, ["clone", "pol-1", "--name", "Copy"])
        assert result.exit_code == 0
        mc.post.assert_called_once()


# ── Schedules — full CRUD ─────────────────────────────────────────────────


class TestSchedulesWrite:
    def test_show(self):
        p, _ = _mock_client("wireghost.cli.schedules.get_client", get_data={
            "id": "sched-1", "name": "Nightly", "target": "10.0.0.0/24",
            "cron": "0 2 * * *", "enabled": True,
        })
        with p:
            result = runner.invoke(schedules_app, ["show", "sched-1"])
        assert result.exit_code == 0
        assert "Nightly" in result.stdout
        assert "0 2 * * *" in result.stdout

    def test_create(self):
        p, mc = _mock_client("wireghost.cli.schedules.get_client")
        with p:
            result = runner.invoke(schedules_app, [
                "create", "--name", "Weekly", "--target", "10.0.0.0/24",
                "--cron", "0 3 * * 0",
            ])
        assert result.exit_code == 0
        body = mc.post.call_args[1]["json"]
        assert body["name"] == "Weekly"
        assert body["cron"] == "0 3 * * 0"

    def test_update(self):
        p, mc = _mock_client("wireghost.cli.schedules.get_client")
        with p:
            result = runner.invoke(schedules_app, [
                "update", "sched-1", "--cron", "0 4 * * *"
            ])
        assert result.exit_code == 0
        body = mc.patch.call_args[1]["json"]
        assert body["cron"] == "0 4 * * *"

    def test_toggle(self):
        p, mc = _mock_client("wireghost.cli.schedules.get_client",
                             post_data={"enabled": True})
        with p:
            result = runner.invoke(schedules_app, ["toggle", "sched-1"])
        assert result.exit_code == 0
        mc.post.assert_called_once()


# ── Users — full CRUD ─────────────────────────────────────────────────────


class TestUsersWrite:
    def test_show(self):
        p, _ = _mock_client("wireghost.cli.users.get_client", get_data={
            "id": "user-1", "username": "alice", "role": "engineer",
            "email": "alice@example.com", "status": "active",
        })
        with p:
            result = runner.invoke(users_app, ["show", "user-1"])
        assert result.exit_code == 0
        assert "alice" in result.stdout
        assert "engineer" in result.stdout

    def test_create_with_prompt(self):
        p, mc = _mock_client("wireghost.cli.users.get_client")
        with p, patch("getpass.getpass", return_value="secret123"):
            result = runner.invoke(users_app, [
                "create", "--username", "bob", "--role", "viewer", "--password-prompt",
            ])
        assert result.exit_code == 0
        body = mc.post.call_args[1]["json"]
        assert body["username"] == "bob"
        assert body["role"] == "viewer"
        assert body["password"] == "secret123"

    def test_create_without_prompt_uses_getpass(self):
        """Without --password-prompt, still prompts via getpass."""
        p, mc = _mock_client("wireghost.cli.users.get_client")
        with p, patch("getpass.getpass", return_value="hunter2"):
            result = runner.invoke(users_app, [
                "create", "--username", "bob", "--role", "viewer",
            ])
        assert result.exit_code == 0
        body = mc.post.call_args[1]["json"]
        assert body["password"] == "hunter2"

    def test_update(self):
        p, mc = _mock_client("wireghost.cli.users.get_client")
        with p:
            result = runner.invoke(users_app, [
                "update", "user-1", "--role", "owner", "--email", "new@example.com"
            ])
        assert result.exit_code == 0
        mc.put.assert_called_once()
        body = mc.put.call_args[1]["json"]
        assert body["role"] == "owner"

    def test_delete_with_force(self):
        p, mc = _mock_client("wireghost.cli.users.get_client")
        with p:
            result = runner.invoke(users_app, ["delete", "user-1", "--force"])
        assert result.exit_code == 0
        mc.delete.assert_called_once()

    def test_reset_password_mismatch(self):
        p, _ = _mock_client("wireghost.cli.users.get_client")
        with p, patch("getpass.getpass", side_effect=["newpass", "mismatch"]):
            result = runner.invoke(users_app, [
                "reset-password", "alice",
            ])
        assert result.exit_code == 1
        assert "do not match" in result.stderr


# ── Tokens — create & revoke ──────────────────────────────────────────────


class TestTokensWrite:
    def test_create_shows_token(self):
        p, _ = _mock_client("wireghost.cli.tokens.get_client", post_data={
            "id": "tok-1", "name": "CLI token", "token": "wg_secret_abc123"
        })
        with p:
            result = runner.invoke(tokens_app, ["create", "--name", "CLI token"])
        assert result.exit_code == 0
        assert "wg_secret_abc123" in result.stderr

    def test_revoke(self):
        p, mc = _mock_client("wireghost.cli.tokens.get_client")
        with p:
            result = runner.invoke(tokens_app, ["revoke", "tok-1"])
        assert result.exit_code == 0
        mc.post.assert_called_once()


# ── Sessions — revoke flows ───────────────────────────────────────────────


class TestSessionsWrite:
    def test_revoke(self):
        p, mc = _mock_client("wireghost.cli.sessions.get_client")
        with p:
            result = runner.invoke(sessions_app, ["revoke", "abc123def456"])
        assert result.exit_code == 0
        mc.post.assert_called_once()

    def test_revoke_all_no_force_denied(self):
        p, _ = _mock_client("wireghost.cli.sessions.get_client")
        with p:
            result = runner.invoke(sessions_app, ["revoke-all"], input="n\n")
        assert result.exit_code == 0

    def test_revoke_all_with_force(self):
        p, mc = _mock_client("wireghost.cli.sessions.get_client")
        with p:
            result = runner.invoke(sessions_app, ["revoke-all", "--force"])
        assert result.exit_code == 0
        mc.post.assert_called_once()


# ── Reports ───────────────────────────────────────────────────────────────


class TestReports:
    def test_download(self, tmp_path):
        p, mc = _mock_client("wireghost.cli.reports.get_client",
                             get_data=b"FAKE_DOCX_CONTENT")
        mc.get.return_value.content = b"FAKE_DOCX_CONTENT"
        mc.get.return_value.json.return_value = {}
        with p:
            result = runner.invoke(reports_app, [
                "download", "deadbeef-dead-beef-dead-beefdeadbeef",
                "--output", str(tmp_path),
            ])
        assert result.exit_code == 0
        files = list(tmp_path.glob("report_*.docx"))
        assert len(files) == 1
        assert files[0].read_bytes() == b"FAKE_DOCX_CONTENT"

    def test_config(self):
        p, _ = _mock_client("wireghost.cli.reports.get_client", get_data={
            "company": "Acme Corp", "logo_url": "https://cdn.example.com/logo.png"
        })
        with p:
            result = runner.invoke(reports_app, ["config"])
        assert result.exit_code == 0
        assert "Acme Corp" in result.stderr

    def test_logo(self, tmp_path):
        logo_file = tmp_path / "logo.png"
        logo_file.write_bytes(b"\x89PNG\r\n\x1a\n")
        p, mc = _mock_client("wireghost.cli.reports.get_client")
        with p:
            result = runner.invoke(reports_app, ["logo", str(logo_file)])
        assert result.exit_code == 0
        mc.post.assert_called_once()

    def test_generate_calls_subprocess(self):
        """generate command shells out to wireghost report subprocess."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            result = runner.invoke(reports_app, [
                "generate", "/tmp/scandir", "-o", "/tmp/out", "-f", "html", "--title", "Test"
            ])
        assert result.exit_code == 0
        mock_run.assert_called_once()


# ── Notifications ─────────────────────────────────────────────────────────


class TestNotificationsRemaining:
    def test_test_notification(self):
        p, mc = _mock_client("wireghost.cli.notifications.get_client")
        with p:
            result = runner.invoke(notifications_app, ["test", "--channel", "email"])
        assert result.exit_code == 0
        mc.post.assert_called_once()
        assert mc.post.call_args[1]["json"]["channel"] == "email"

    def test_config_masks_token(self):
        """Token >20 chars is shown as first 20 chars + '...'."""
        p, _ = _mock_client("wireghost.cli.notifications.get_client", get_data={
            "telegram_bot_token": "12345678901234567890abcdef",
            "enabled": True,
            "on_finding": True,
            "on_scan_complete": False,
        })
        with p:
            result = runner.invoke(notifications_app, ["config"])
        assert result.exit_code == 0
        # Masked portion shown
        assert "12345678901234567890..." in result.stdout
        # Full token NOT shown
        assert "abcdef" not in result.stdout
        # Other fields visible
        assert "True" in result.stdout

    def test_config_no_token_shows_dash(self):
        """Empty/missing token shows em-dash."""
        p, _ = _mock_client("wireghost.cli.notifications.get_client", get_data={
            "enabled": False,
            "on_finding": False,
            "on_scan_complete": False,
        })
        with p:
            result = runner.invoke(notifications_app, ["config"])
        assert result.exit_code == 0
        # echo_keyvalue falls through to JSON (non-TTY), em-dash is —
        assert "—" in result.stdout or "\\u2014" in result.stdout

    def test_config_short_token_still_masked(self):
        """Even short tokens get masked with '...'."""
        p, _ = _mock_client("wireghost.cli.notifications.get_client", get_data={
            "telegram_bot_token": "short",
            "enabled": True,
            "on_finding": False,
            "on_scan_complete": False,
        })
        with p:
            result = runner.invoke(notifications_app, ["config"])
        assert result.exit_code == 0
        assert "short..." in result.stdout


# ── Dashboard remaining ───────────────────────────────────────────────────


class TestDashboardRemaining:
    def test_screenshots(self):
        p, _ = _mock_client("wireghost.cli.dashboard.get_client", get_data=[
            {"id": "ss-1", "url": "https://example.com", "host": "10.0.0.1",
             "port": 443, "title": "Dashboard"}
        ])
        with p:
            result = runner.invoke(dashboard_app, ["screenshots"])
        assert result.exit_code == 0

    def test_screenshots_with_scan_filter(self):
        p, _ = _mock_client("wireghost.cli.dashboard.get_client", get_data=[])
        with p:
            result = runner.invoke(dashboard_app, [
                "screenshots", "--scan", "deadbeef", "--limit", "10"
            ])
        assert result.exit_code == 0


# ── System remaining commands ─────────────────────────────────────────────


class TestSystemRemaining:
    def test_processes(self):
        p, _ = _mock_client("wireghost.cli.system.get_client", get_data=[
            {"name": "nmap", "pid": 1234, "cpu": "5.0", "mem": "2.1", "status": "running"}
        ])
        with p:
            result = runner.invoke(system_app, ["processes"])
        assert result.exit_code == 0

    def test_audit(self):
        p, _ = _mock_client("wireghost.cli.system.get_client", get_data=[
            {"timestamp": "2025-01-01", "user": "admin", "action": "login", "detail": "-"}
        ])
        with p:
            result = runner.invoke(system_app, ["audit", "--limit", "10"])
        assert result.exit_code == 0

    def test_update_check_only(self):
        p, _ = _mock_client("wireghost.cli.system.get_client", get_data={
            "current": "2.0.0", "latest": "2.1.0", "update_available": True
        })
        with p:
            result = runner.invoke(system_app, ["update"])
        assert result.exit_code == 0
        assert "2.0.0" in result.stdout

    def test_update_apply_tools_and_feeds(self):
        p, mc = _mock_client("wireghost.cli.system.get_client")
        with p:
            result = runner.invoke(system_app, ["update", "--tools", "--feeds"])
        assert result.exit_code == 0
        assert mc.post.call_count == 2

    def test_feeds(self):
        p, _ = _mock_client("wireghost.cli.system.get_client", get_data={
            "nuclei_templates": "9,847", "searchsploit_db": "56,291", "msf_metadata": "loaded"
        })
        with p:
            result = runner.invoke(system_app, ["feeds"])
        assert result.exit_code == 0


# ── Findings detail ───────────────────────────────────────────────────────


class TestFindingsDetail:
    def test_show(self):
        p, _ = _mock_client("wireghost.cli.findings.get_client", get_data={
            "id": "f-1", "title": "SQL Injection", "severity": "critical",
            "host": "10.0.0.1", "port": 3306, "cve": "CVE-2024-0001",
            "description": "Blind SQLi in login form",
        })
        with p:
            result = runner.invoke(findings_app, ["show", "f-1"])
        assert result.exit_code == 0
        assert "SQL Injection" in result.stdout
        assert "CVE-2024-0001" in result.stdout

    def test_toggle_fp(self):
        p, mc = _mock_client("wireghost.cli.findings.get_client",
                             patch_data={"false_positive": True})
        with p:
            result = runner.invoke(findings_app, ["toggle", "f-1"])
        assert result.exit_code == 0
        mc.patch.assert_called_once()


# ── Hosts detail ──────────────────────────────────────────────────────────


class TestHostsDetail:
    def test_show(self):
        p, _ = _mock_client("wireghost.cli.hosts.get_client", get_data={
            "ip": "10.0.0.1", "hostname": "web01.example.com",
            "os": "Linux 5.15", "open_ports": 12, "status": "up",
        })
        with p:
            result = runner.invoke(hosts_app, ["show", "10.0.0.1"])
        assert result.exit_code == 0
        assert "web01.example.com" in result.stdout

    def test_topology(self):
        p, _ = _mock_client("wireghost.cli.hosts.get_client", get_data={
            "nodes": [{"id": "10.0.0.1"}], "edges": []
        })
        with p:
            result = runner.invoke(hosts_app, ["topology", "deadbeef"])
        assert result.exit_code == 0


# ── Exploits detail ───────────────────────────────────────────────────────


class TestExploitsDetail:
    def test_show(self):
        p, _ = _mock_client("wireghost.cli.exploits.get_client", get_data={
            "id": "e-1", "name": "MS17-010 EternalBlue", "service": "microsoft-ds",
            "host": "10.0.0.1", "port": 445, "severity": "critical",
        })
        with p:
            result = runner.invoke(exploits_app, ["show", "e-1"])
        assert result.exit_code == 0
        assert "EternalBlue" in result.stdout


# ── JSON output mode ──────────────────────────────────────────────────────


class TestJsonMode:
    """Test echo_json/echo_keyvalue directly — check_json_flag() is untestable
    via CliRunner because it reads global sys.argv."""

    def test_echo_json_writes_json_to_stdout(self, capsys):
        import json
        from wireghost.cli.output import echo_json
        data = {"key": "value", "nested": [1, 2, 3]}
        echo_json(data)
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed == data

    def test_echo_keyvalue_formats_pairs(self, capsys):
        from wireghost.cli.output import echo_keyvalue
        echo_keyvalue([("Name:", "test"), ("Count:", 42)])
        captured = capsys.readouterr()
        assert "Name:" in captured.out
        assert "test" in captured.out
        assert "42" in captured.out


# ── Error handling — 4xx/5xx/network ──────────────────────────────────────


class TestErrorHandling:
    def test_403_forbidden_exits_1(self):
        p, mc = _mock_client("wireghost.cli.findings.get_client")
        mc.get.return_value = _resp(403, {"detail": "Forbidden"})
        with p:
            result = runner.invoke(findings_app, ["list"])
        assert result.exit_code == 1

    def test_500_server_error_exits_1(self):
        p, mc = _mock_client("wireghost.cli.scans.get_client")
        mc.get.return_value = _resp(500, {"detail": "Internal error"})
        with p:
            result = runner.invoke(scans_app, ["list"])
        assert result.exit_code == 1

    def test_network_error_exits_1(self):
        p, mc = _mock_client("wireghost.cli.policies.get_client")
        mc.get.side_effect = httpx.ConnectError("Connection refused")
        with p:
            result = runner.invoke(policies_app, ["list"])
        assert result.exit_code == 1

    def test_timeout_error_exits_1(self):
        p, mc = _mock_client("wireghost.cli.dashboard.get_client")
        mc.get.side_effect = httpx.ReadTimeout("timed out")
        with p:
            result = runner.invoke(dashboard_app, ["stats"])
        assert result.exit_code == 1


# ── Dispatcher ────────────────────────────────────────────────────────────


class TestDispatcher:
    def test_version_flag(self):
        result = runner.invoke(dispatcher.app, ["--version"])
        assert result.exit_code == 0
        assert "wireghost" in result.stdout

    def test_help_shows_all_groups(self):
        result = runner.invoke(dispatcher.app, ["--help"])
        assert result.exit_code == 0
        expected_groups = [
            "auth", "scan", "scans", "hosts", "findings", "policies",
            "schedules", "exploits", "users", "tokens", "sessions",
            "system", "report", "notify", "dashboard", "support-bundle",
        ]
        for group in expected_groups:
            assert group in result.stdout, f"Missing group: {group}"

    def test_config_init_file_exists(self):
        with patch("wireghost.cli.dispatcher.Path.exists", return_value=True):
            result = runner.invoke(dispatcher.app, ["config", "init"])
        assert result.exit_code == 1  # already exists
        assert "already exists" in result.stderr

    def test_config_show(self):
        mock_cfg = MagicMock()
        mock_cfg.target = "10.0.0.0/24"
        mock_cfg.parallelism = 10
        mock_cfg.skip_nuclei = False
        mock_cfg.report_formats = ["html", "docx"]
        mock_cfg.report_title = "Test Report"
        for attr in ["output_dir", "version_detect", "os_detect", "service_enum",
                      "skip_vuln", "tool_timeout", "verbose"]:
            setattr(mock_cfg, attr, True)
        with patch("wireghost.config.ScanConfig") as cfg_cls:
            cfg_cls.load.return_value = mock_cfg
            result = runner.invoke(dispatcher.app, ["config", "show"])
        assert result.exit_code == 0
