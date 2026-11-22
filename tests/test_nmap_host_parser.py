"""Tests for the nmap host-output parser used by discovery.

nmap's raw output mentions IPs that are NOT live hosts — most importantly
the "Warning: <ip> giving up on port because retransmission cap hit (0)."
lines, which nmap writes to stdout.  Picking up every IP-looking string
turns a dead range into a list of "live hosts", so the parser must only
honour real "Nmap scan report for ..." / "Host is up" blocks.
"""

from __future__ import annotations

from wireghost.pipeline.discovery import _parse_nmap_hosts


class TestParseNmapHosts:
    def test_plain_report(self):
        stdout = (
            "Nmap scan report for 172.26.0.1\n"
            "Host is up (0.000056s latency).\n"
            "MAC Address: 06:48:BA:7F:67:BA (Unknown)\n"
        )
        assert _parse_nmap_hosts(stdout) == ["172.26.0.1"]

    def test_report_with_hostname(self):
        stdout = (
            "Nmap scan report for db-1.internal (172.26.0.2)\n"
            "Host is up (0.0000070s latency).\n"
        )
        assert _parse_nmap_hosts(stdout) == ["172.26.0.2"]

    def test_multiple_hosts(self):
        stdout = (
            "Nmap scan report for 10.0.0.1\n"
            "Host is up (0.01s latency).\n"
            "Nmap scan report for 10.0.0.2\n"
            "Host is up (0.02s latency).\n"
        )
        assert _parse_nmap_hosts(stdout) == ["10.0.0.1", "10.0.0.2"]

    def test_warning_lines_are_not_hosts(self):
        """nmap writes "giving up on port" warnings to stdout."""
        stdout = (
            "Warning: 10.20.0.67 giving up on port because retransmission cap hit (0).\n"
            "Warning: 10.20.0.104 giving up on port because retransmission cap hit (0).\n"
            "Nmap done: 256 IP addresses (0 hosts up) scanned in 2.07 seconds\n"
        )
        assert _parse_nmap_hosts(stdout) == []

    def test_warnings_do_not_hide_real_hosts(self):
        stdout = (
            "Warning: 10.20.0.67 giving up on port because retransmission cap hit (0).\n"
            "Nmap scan report for 10.20.0.5\n"
            "Host is up (0.01s latency).\n"
            "Warning: 10.20.0.104 giving up on port because retransmission cap hit (0).\n"
        )
        assert _parse_nmap_hosts(stdout) == ["10.20.0.5"]

    def test_report_without_host_up_is_ignored(self):
        stdout = "Nmap scan report for 10.0.0.9\n"
        assert _parse_nmap_hosts(stdout) == []

    def test_hostname_only_report_is_ignored(self):
        stdout = (
            "Nmap scan report for some.host.example\n"
            "Host is up (0.01s latency).\n"
        )
        assert _parse_nmap_hosts(stdout) == []

    def test_empty_output(self):
        assert _parse_nmap_hosts("") == []
