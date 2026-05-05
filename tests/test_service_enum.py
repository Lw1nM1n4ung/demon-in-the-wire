"""Tests for wireghost.pipeline.service_enum — pure Python service checks."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from wireghost.models.severity import Severity
from wireghost.pipeline.service_enum import (
    _check_docker,
    _check_elasticsearch,
    _check_ftp,
    _check_ldap,
    _check_memcached,
    _check_mongodb,
    _check_mysql,
    _check_postgresql,
    _check_rdp,
    _check_redis,
    _check_smtp,
    _check_ssh,
    _check_telnet,
    _check_vnc,
    enumerate_services,
)

IP = "10.0.0.1"


class TestCheckSsh:
    @patch("wireghost.pipeline.service_enum._tcp_banner", new_callable=AsyncMock)
    async def test_ssh_banner(self, mock_banner):
        mock_banner.return_value = "SSH-2.0-OpenSSH_8.9p1"
        findings = await _check_ssh(IP, 22)
        assert len(findings) == 1
        assert "OpenSSH" in findings[0].title
        assert findings[0].severity == Severity.INFO

    @patch("wireghost.pipeline.service_enum._tcp_banner", new_callable=AsyncMock)
    async def test_ssh_no_banner(self, mock_banner):
        mock_banner.return_value = ""
        findings = await _check_ssh(IP, 22)
        assert findings == []


class TestCheckFtp:
    @patch("wireghost.pipeline.service_enum._tcp_connect", new_callable=AsyncMock)
    async def test_ftp_anonymous(self, mock_connect):
        reader = AsyncMock()
        reader.read = AsyncMock(side_effect=[
            b"220 vsftpd 3.0.3\r\n",
            b"331 Please specify the password.\r\n",
            b"230 Login successful.\r\n",
        ])
        writer = MagicMock()
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.close = MagicMock()
        mock_connect.return_value = (reader, writer)

        findings = await _check_ftp(IP, 21)
        assert len(findings) == 2
        anon = [f for f in findings if "Anonymous" in f.title]
        assert len(anon) == 1
        assert anon[0].severity == Severity.HIGH

    @patch("wireghost.pipeline.service_enum._tcp_connect", new_callable=AsyncMock)
    async def test_ftp_no_connect(self, mock_connect):
        mock_connect.return_value = None
        findings = await _check_ftp(IP, 21)
        assert findings == []


class TestCheckRedis:
    @patch("wireghost.pipeline.service_enum._tcp_send_recv", new_callable=AsyncMock)
    async def test_redis_no_auth(self, mock_send):
        mock_send.side_effect = [b"+PONG\r\n", b"redis_version:7.0.1\r\n"]
        findings = await _check_redis(IP, 6379)
        assert len(findings) == 2
        no_auth = [f for f in findings if "No Authentication" in f.title]
        assert len(no_auth) == 1
        assert no_auth[0].severity == Severity.HIGH

    @patch("wireghost.pipeline.service_enum._tcp_send_recv", new_callable=AsyncMock)
    async def test_redis_requires_auth(self, mock_send):
        mock_send.return_value = b"-NOAUTH Authentication required.\r\n"
        findings = await _check_redis(IP, 6379)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    @patch("wireghost.pipeline.service_enum._tcp_send_recv", new_callable=AsyncMock)
    async def test_redis_closed(self, mock_send):
        mock_send.return_value = b""
        findings = await _check_redis(IP, 6379)
        assert findings == []


class TestCheckMysql:
    @patch("wireghost.pipeline.service_enum._tcp_banner", new_callable=AsyncMock)
    async def test_mysql_version(self, mock_banner):
        raw = b"\x00\x00\x00\x00\x0a5.7.42\x00"
        mock_banner.return_value = raw.decode("latin-1", errors="replace")
        findings = await _check_mysql(IP, 3306)
        assert len(findings) == 1
        assert "5.7.42" in findings[0].title

    @patch("wireghost.pipeline.service_enum._tcp_banner", new_callable=AsyncMock)
    async def test_mysql_no_banner(self, mock_banner):
        mock_banner.return_value = ""
        findings = await _check_mysql(IP, 3306)
        assert findings == []


class TestCheckPostgresql:
    @patch("wireghost.pipeline.service_enum._tcp_send_recv", new_callable=AsyncMock)
    async def test_pg_trust_auth(self, mock_send):
        import struct
        mock_send.return_value = b'R' + b'\x00\x00\x00\x08' + struct.pack(">I", 0)
        findings = await _check_postgresql(IP, 5432)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "No Password Required" in findings[0].title

    @patch("wireghost.pipeline.service_enum._tcp_send_recv", new_callable=AsyncMock)
    async def test_pg_md5_auth(self, mock_send):
        import struct
        mock_send.return_value = b'R' + b'\x00\x00\x00\x08' + struct.pack(">I", 5) + b'\x00' * 4
        findings = await _check_postgresql(IP, 5432)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "MD5" in findings[0].title

    @patch("wireghost.pipeline.service_enum._tcp_send_recv", new_callable=AsyncMock)
    async def test_pg_no_response(self, mock_send):
        mock_send.return_value = b""
        findings = await _check_postgresql(IP, 5432)
        assert findings == []


class TestCheckSmtp:
    @patch("wireghost.pipeline.service_enum._tcp_connect", new_callable=AsyncMock)
    async def test_smtp_vrfy(self, mock_connect):
        reader = AsyncMock()
        reader.read = AsyncMock(side_effect=[
            b"220 mail.test.local ESMTP\r\n",
            b"250-Hello\r\n250 VRFY\r\n",
        ])
        writer = MagicMock()
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.close = MagicMock()
        mock_connect.return_value = (reader, writer)

        findings = await _check_smtp(IP, 25)
        assert len(findings) == 2
        vrfy = [f for f in findings if "VRFY" in f.title]
        assert len(vrfy) == 1
        assert vrfy[0].severity == Severity.MEDIUM

    @patch("wireghost.pipeline.service_enum._tcp_connect", new_callable=AsyncMock)
    async def test_smtp_no_connect(self, mock_connect):
        mock_connect.return_value = None
        findings = await _check_smtp(IP, 25)
        assert findings == []


class TestCheckLdap:
    @patch("wireghost.pipeline.service_enum._tcp_send_recv", new_callable=AsyncMock)
    async def test_ldap_anonymous_bind(self, mock_send):
        mock_send.return_value = b'\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00'
        findings = await _check_ldap(IP, 389)
        assert len(findings) == 1
        assert "Anonymous Bind" in findings[0].title
        assert findings[0].severity == Severity.HIGH

    @patch("wireghost.pipeline.service_enum._tcp_send_recv", new_callable=AsyncMock)
    async def test_ldap_no_response(self, mock_send):
        mock_send.return_value = b""
        findings = await _check_ldap(IP, 389)
        assert findings == []


class TestCheckMemcached:
    @patch("wireghost.pipeline.service_enum._tcp_send_recv", new_callable=AsyncMock)
    async def test_memcached_no_auth(self, mock_send):
        mock_send.return_value = b"STAT pid 12345\r\nSTAT uptime 3600\r\n"
        findings = await _check_memcached(IP, 11211)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    @patch("wireghost.pipeline.service_enum._tcp_send_recv", new_callable=AsyncMock)
    async def test_memcached_closed(self, mock_send):
        mock_send.return_value = b""
        findings = await _check_memcached(IP, 11211)
        assert findings == []


class TestCheckRdp:
    @patch("wireghost.pipeline.service_enum._tcp_connect", new_callable=AsyncMock)
    async def test_rdp_detected(self, mock_connect):
        writer = MagicMock()
        writer.close = MagicMock()
        mock_connect.return_value = (AsyncMock(), writer)
        findings = await _check_rdp(IP, 3389)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    @patch("wireghost.pipeline.service_enum._tcp_connect", new_callable=AsyncMock)
    async def test_rdp_closed(self, mock_connect):
        mock_connect.return_value = None
        findings = await _check_rdp(IP, 3389)
        assert findings == []


class TestCheckTelnet:
    @patch("wireghost.pipeline.service_enum._tcp_banner", new_callable=AsyncMock)
    async def test_telnet_banner(self, mock_banner):
        mock_banner.return_value = "Welcome to device"
        findings = await _check_telnet(IP, 23)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    @patch("wireghost.pipeline.service_enum._tcp_banner", new_callable=AsyncMock)
    async def test_telnet_no_banner(self, mock_banner):
        mock_banner.return_value = ""
        findings = await _check_telnet(IP, 23)
        assert findings == []


class TestCheckMongodb:
    @patch("wireghost.pipeline.service_enum._tcp_connect", new_callable=AsyncMock)
    @patch("wireghost.pipeline.service_enum._tcp_banner", new_callable=AsyncMock)
    async def test_mongodb_banner(self, mock_banner, mock_connect):
        mock_banner.return_value = "It looks like you are trying to access MongoDB"
        findings = await _check_mongodb(IP, 27017)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    @patch("wireghost.pipeline.service_enum._tcp_connect", new_callable=AsyncMock)
    @patch("wireghost.pipeline.service_enum._tcp_banner", new_callable=AsyncMock)
    async def test_mongodb_no_banner_but_connects(self, mock_banner, mock_connect):
        mock_banner.return_value = ""
        writer = MagicMock()
        writer.close = MagicMock()
        mock_connect.return_value = (AsyncMock(), writer)
        findings = await _check_mongodb(IP, 27017)
        assert len(findings) == 1
        assert "Accepts Connections" in findings[0].title


class TestCheckVnc:
    @patch("wireghost.pipeline.service_enum._tcp_connect", new_callable=AsyncMock)
    @patch("wireghost.pipeline.service_enum._tcp_banner", new_callable=AsyncMock)
    async def test_vnc_no_auth(self, mock_banner, mock_connect):
        mock_banner.return_value = "RFB 003.008"
        reader = AsyncMock()
        reader.read = AsyncMock(side_effect=[
            b"RFB 003.008\n",
            bytes([2, 1, 2]),
        ])
        writer = MagicMock()
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.close = MagicMock()
        mock_connect.return_value = (reader, writer)

        findings = await _check_vnc(IP, 5900)
        assert len(findings) == 2
        no_auth = [f for f in findings if "No Authentication" in f.title]
        assert len(no_auth) == 1
        assert no_auth[0].severity == Severity.CRITICAL

    @patch("wireghost.pipeline.service_enum._tcp_connect", new_callable=AsyncMock)
    @patch("wireghost.pipeline.service_enum._tcp_banner", new_callable=AsyncMock)
    async def test_vnc_no_banner(self, mock_banner, mock_connect):
        mock_banner.return_value = ""
        findings = await _check_vnc(IP, 5900)
        assert findings == []


class TestAllSourcesServiceEnum:
    @patch("wireghost.pipeline.service_enum._tcp_banner", new_callable=AsyncMock)
    async def test_source_is_service_enum(self, mock_banner):
        mock_banner.return_value = "SSH-2.0-OpenSSH_8.9"
        findings = await _check_ssh(IP, 22)
        assert all(f.source == "service_enum" for f in findings)

    @patch("wireghost.pipeline.service_enum._tcp_banner", new_callable=AsyncMock)
    async def test_host_ip_set(self, mock_banner):
        mock_banner.return_value = "SSH-2.0-OpenSSH_8.9"
        findings = await _check_ssh(IP, 22)
        assert all(f.host == IP for f in findings)
