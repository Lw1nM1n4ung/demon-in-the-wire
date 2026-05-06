"""Tests for masscan and naabu output parsers."""

from __future__ import annotations

from pathlib import Path

from wireghost.parsers.masscan import parse_masscan_xml
from wireghost.parsers.naabu import parse_naabu_json


# ================================================================
# masscan XML parser
# ================================================================


class TestParseMasscanXml:
    def test_single_host_single_port(self, tmp_path: Path):
        xml = tmp_path / "masscan.xml"
        xml.write_text(
            '<?xml version="1.0"?>\n'
            "<nmaprun>\n"
            '  <host><address addr="10.0.0.1" addrtype="ipv4"/>\n'
            '    <ports><port protocol="tcp" portid="80">\n'
            '      <state state="open"/>\n'
            "    </port></ports>\n"
            "  </host>\n"
            "</nmaprun>\n"
        )
        hosts = parse_masscan_xml(xml)
        assert len(hosts) == 1
        assert hosts[0].ip == "10.0.0.1"
        assert len(hosts[0].ports) == 1
        assert hosts[0].ports[0].number == 80

    def test_multiple_hosts(self, tmp_path: Path):
        xml = tmp_path / "masscan.xml"
        xml.write_text(
            '<?xml version="1.0"?>\n'
            "<nmaprun>\n"
            '  <host><address addr="10.0.0.2" addrtype="ipv4"/>\n'
            '    <ports><port protocol="tcp" portid="22">'
            '<state state="open"/></port></ports></host>\n'
            '  <host><address addr="10.0.0.1" addrtype="ipv4"/>\n'
            '    <ports><port protocol="tcp" portid="443">'
            '<state state="open"/></port></ports></host>\n'
            "</nmaprun>\n"
        )
        hosts = parse_masscan_xml(xml)
        assert len(hosts) == 2
        assert hosts[0].ip == "10.0.0.1"
        assert hosts[1].ip == "10.0.0.2"

    def test_multiple_ports_same_host(self, tmp_path: Path):
        xml = tmp_path / "masscan.xml"
        xml.write_text(
            '<?xml version="1.0"?>\n'
            "<nmaprun>\n"
            '  <host><address addr="10.0.0.1" addrtype="ipv4"/>\n'
            "    <ports>\n"
            '      <port protocol="tcp" portid="22"><state state="open"/></port>\n'
            '      <port protocol="tcp" portid="80"><state state="open"/></port>\n'
            '      <port protocol="tcp" portid="443"><state state="open"/></port>\n'
            "    </ports>\n"
            "  </host>\n"
            "</nmaprun>\n"
        )
        hosts = parse_masscan_xml(xml)
        assert len(hosts) == 1
        assert len(hosts[0].ports) == 3

    def test_filtered_port_excluded(self, tmp_path: Path):
        xml = tmp_path / "masscan.xml"
        xml.write_text(
            '<?xml version="1.0"?>\n'
            "<nmaprun>\n"
            '  <host><address addr="10.0.0.1" addrtype="ipv4"/>\n'
            "    <ports>\n"
            '      <port protocol="tcp" portid="22"><state state="open"/></port>\n'
            '      <port protocol="tcp" portid="80"><state state="filtered"/></port>\n'
            "    </ports>\n"
            "  </host>\n"
            "</nmaprun>\n"
        )
        hosts = parse_masscan_xml(xml)
        assert len(hosts) == 1
        assert len(hosts[0].ports) == 1
        assert hosts[0].ports[0].number == 22

    def test_missing_file(self, tmp_path: Path):
        hosts = parse_masscan_xml(tmp_path / "nonexistent.xml")
        assert hosts == []

    def test_malformed_xml(self, tmp_path: Path):
        xml = tmp_path / "masscan.xml"
        xml.write_text("<<<not xml>>>")
        hosts = parse_masscan_xml(xml)
        assert hosts == []

    def test_empty_xml(self, tmp_path: Path):
        xml = tmp_path / "masscan.xml"
        xml.write_text('<?xml version="1.0"?>\n<nmaprun></nmaprun>\n')
        hosts = parse_masscan_xml(xml)
        assert hosts == []

    def test_host_without_address(self, tmp_path: Path):
        xml = tmp_path / "masscan.xml"
        xml.write_text(
            '<?xml version="1.0"?>\n'
            "<nmaprun>\n"
            "  <host>\n"
            '    <ports><port protocol="tcp" portid="80">'
            '<state state="open"/></port></ports>\n'
            "  </host>\n"
            "</nmaprun>\n"
        )
        hosts = parse_masscan_xml(xml)
        assert hosts == []

    def test_port_protocol_preserved(self, tmp_path: Path):
        xml = tmp_path / "masscan.xml"
        xml.write_text(
            '<?xml version="1.0"?>\n'
            "<nmaprun>\n"
            '  <host><address addr="10.0.0.1" addrtype="ipv4"/>\n'
            '    <ports><port protocol="udp" portid="161">'
            '<state state="open"/></port></ports>\n'
            "  </host>\n"
            "</nmaprun>\n"
        )
        hosts = parse_masscan_xml(xml)
        assert hosts[0].ports[0].protocol == "udp"

    def test_all_ports_open_state(self, tmp_path: Path):
        xml = tmp_path / "masscan.xml"
        xml.write_text(
            '<?xml version="1.0"?>\n'
            "<nmaprun>\n"
            '  <host><address addr="10.0.0.1" addrtype="ipv4"/>\n'
            '    <ports><port protocol="tcp" portid="80">'
            '<state state="open"/></port></ports>\n'
            "  </host>\n"
            "</nmaprun>\n"
        )
        hosts = parse_masscan_xml(xml)
        assert hosts[0].ports[0].state == "open"

    def test_port_without_state_defaults_open(self, tmp_path: Path):
        xml = tmp_path / "masscan.xml"
        xml.write_text(
            '<?xml version="1.0"?>\n'
            "<nmaprun>\n"
            '  <host><address addr="10.0.0.1" addrtype="ipv4"/>\n'
            '    <ports><port protocol="tcp" portid="80"></port></ports>\n'
            "  </host>\n"
            "</nmaprun>\n"
        )
        hosts = parse_masscan_xml(xml)
        assert len(hosts[0].ports) == 1
        assert hosts[0].ports[0].state == "open"


# ================================================================
# naabu JSONL parser
# ================================================================


class TestParseNaabuJson:
    def test_single_host(self, tmp_path: Path):
        f = tmp_path / "naabu.json"
        f.write_text('{"ip":"10.0.0.1","port":80,"protocol":"tcp"}\n')
        hosts = parse_naabu_json(f)
        assert len(hosts) == 1
        assert hosts[0].ip == "10.0.0.1"
        assert hosts[0].ports[0].number == 80

    def test_multiple_hosts(self, tmp_path: Path):
        f = tmp_path / "naabu.json"
        f.write_text(
            '{"ip":"10.0.0.2","port":22,"protocol":"tcp"}\n'
            '{"ip":"10.0.0.1","port":80,"protocol":"tcp"}\n'
        )
        hosts = parse_naabu_json(f)
        assert len(hosts) == 2
        assert hosts[0].ip == "10.0.0.1"
        assert hosts[1].ip == "10.0.0.2"

    def test_multiple_ports_grouped(self, tmp_path: Path):
        f = tmp_path / "naabu.json"
        f.write_text(
            '{"ip":"10.0.0.1","port":22,"protocol":"tcp"}\n'
            '{"ip":"10.0.0.1","port":80,"protocol":"tcp"}\n'
            '{"ip":"10.0.0.1","port":443,"protocol":"tcp"}\n'
        )
        hosts = parse_naabu_json(f)
        assert len(hosts) == 1
        assert len(hosts[0].ports) == 3

    def test_missing_file(self, tmp_path: Path):
        hosts = parse_naabu_json(tmp_path / "nonexistent.json")
        assert hosts == []

    def test_empty_file(self, tmp_path: Path):
        f = tmp_path / "naabu.json"
        f.write_text("")
        hosts = parse_naabu_json(f)
        assert hosts == []

    def test_malformed_json_line_skipped(self, tmp_path: Path):
        f = tmp_path / "naabu.json"
        f.write_text(
            '{"ip":"10.0.0.1","port":80,"protocol":"tcp"}\n'
            "not json at all\n"
            '{"ip":"10.0.0.1","port":443,"protocol":"tcp"}\n'
        )
        hosts = parse_naabu_json(f)
        assert len(hosts) == 1
        assert len(hosts[0].ports) == 2

    def test_missing_ip_skipped(self, tmp_path: Path):
        f = tmp_path / "naabu.json"
        f.write_text('{"port":80,"protocol":"tcp"}\n')
        hosts = parse_naabu_json(f)
        assert hosts == []

    def test_missing_port_skipped(self, tmp_path: Path):
        f = tmp_path / "naabu.json"
        f.write_text('{"ip":"10.0.0.1","protocol":"tcp"}\n')
        hosts = parse_naabu_json(f)
        assert hosts == []

    def test_blank_lines_skipped(self, tmp_path: Path):
        f = tmp_path / "naabu.json"
        f.write_text(
            "\n\n"
            '{"ip":"10.0.0.1","port":22,"protocol":"tcp"}\n'
            "\n"
        )
        hosts = parse_naabu_json(f)
        assert len(hosts) == 1

    def test_default_protocol_tcp(self, tmp_path: Path):
        f = tmp_path / "naabu.json"
        f.write_text('{"ip":"10.0.0.1","port":80}\n')
        hosts = parse_naabu_json(f)
        assert hosts[0].ports[0].protocol == "tcp"

    def test_all_ports_open(self, tmp_path: Path):
        f = tmp_path / "naabu.json"
        f.write_text('{"ip":"10.0.0.1","port":80,"protocol":"tcp"}\n')
        hosts = parse_naabu_json(f)
        assert hosts[0].ports[0].state == "open"

    def test_non_dict_line_skipped(self, tmp_path: Path):
        f = tmp_path / "naabu.json"
        f.write_text(
            '"just a string"\n'
            '{"ip":"10.0.0.1","port":80,"protocol":"tcp"}\n'
        )
        hosts = parse_naabu_json(f)
        assert len(hosts) == 1
