"""Service-specific enumeration — pure Python, no nmap NSE.

For each detected service: connect, banner grab, check auth, enumerate data.
Never brute force.
"""

from __future__ import annotations

import asyncio
import logging
import struct
from typing import TYPE_CHECKING

import aiohttp

from wireghost.models.finding import Finding
from wireghost.models.severity import Severity

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.models.scan import Host
    from wireghost.utils.fs import OutputTree

log = logging.getLogger("wireghost")
_TIMEOUT = 5


# ── Helpers ──────────────────────────────────────────────

async def _tcp_connect(ip: str, port: int):
    try:
        return await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=_TIMEOUT)
    except Exception:
        return None


async def _tcp_banner(ip: str, port: int) -> str:
    conn = await _tcp_connect(ip, port)
    if not conn:
        return ""
    reader, writer = conn
    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=_TIMEOUT)
        return data.decode(errors="replace").strip()
    except Exception:
        return ""
    finally:
        writer.close()


async def _tcp_send_recv(ip: str, port: int, payload: bytes, read_size: int = 4096) -> bytes:
    conn = await _tcp_connect(ip, port)
    if not conn:
        return b""
    reader, writer = conn
    try:
        writer.write(payload)
        await writer.drain()
        return await asyncio.wait_for(reader.read(read_size), timeout=_TIMEOUT)
    except Exception:
        return b""
    finally:
        writer.close()


def _f(ip: str, port: int, title: str, sev: Severity, desc: str, raw: str = "") -> Finding:
    return Finding(
        source="service_enum", host=ip, port=str(port), protocol="tcp",
        severity=sev, title=title, description=desc, raw_output=raw,
    )


# ── Service Checks ───────────────────────────────────────

async def _check_ssh(ip: str, port: int) -> list[Finding]:
    banner = await _tcp_banner(ip, port)
    if not banner:
        return []
    return [_f(ip, port, f"SSH: {banner.split(chr(10))[0][:60]}", Severity.INFO,
               f"SSH service detected.\nBanner: {banner}")]


async def _check_ftp(ip: str, port: int) -> list[Finding]:
    findings: list[Finding] = []
    conn = await _tcp_connect(ip, port)
    if not conn:
        return []
    reader, writer = conn
    try:
        banner = (await asyncio.wait_for(reader.read(1024), timeout=_TIMEOUT)).decode(errors="replace").strip()
        findings.append(_f(ip, port, f"FTP: {banner[:60]}", Severity.INFO, banner))
        writer.write(b"USER anonymous\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.read(1024), timeout=_TIMEOUT)
        writer.write(b"PASS anonymous@\r\n")
        await writer.drain()
        resp = (await asyncio.wait_for(reader.read(1024), timeout=_TIMEOUT)).decode(errors="replace")
        if "230" in resp:
            findings.append(_f(ip, port, "FTP: Anonymous Login Allowed", Severity.HIGH,
                               "FTP allows anonymous access without credentials.", resp))
    except Exception:
        pass
    finally:
        writer.close()
    return findings


async def _check_redis(ip: str, port: int) -> list[Finding]:
    findings: list[Finding] = []
    resp = await _tcp_send_recv(ip, port, b"PING\r\n")
    if b"+PONG" in resp:
        findings.append(_f(ip, port, "Redis: No Authentication Required", Severity.HIGH,
                           "Redis accepts commands without auth. Full data access possible."))
        info = await _tcp_send_recv(ip, port, b"INFO\r\n", 8192)
        if info and b"redis_version" in info:
            findings.append(_f(ip, port, "Redis: Server Info Exposed", Severity.MEDIUM,
                               "Redis INFO accessible.", info.decode(errors="replace")[:2000]))
    elif b"-NOAUTH" in resp:
        findings.append(_f(ip, port, "Redis: Authentication Required", Severity.INFO,
                           "Redis requires authentication."))
    return findings


async def _check_mongodb(ip: str, port: int) -> list[Finding]:
    banner = await _tcp_banner(ip, port)
    if banner and ("MongoDB" in banner or "It looks like" in banner):
        return [_f(ip, port, "MongoDB: Service Detected", Severity.INFO, f"Banner: {banner[:200]}")]
    # Try raw connect — MongoDB sends something on connect
    conn = await _tcp_connect(ip, port)
    if conn:
        conn[1].close()
        return [_f(ip, port, "MongoDB: Accepts Connections", Severity.INFO,
                   "MongoDB port accepts TCP connections.")]
    return []


async def _check_mysql(ip: str, port: int) -> list[Finding]:
    banner = await _tcp_banner(ip, port)
    if not banner:
        return []
    version = ""
    try:
        raw = banner.encode("latin-1", errors="replace")
        if len(raw) > 5 and raw[4] == 10:
            end = raw.index(0, 5) if 0 in raw[5:] else len(raw)
            version = raw[5:end].decode(errors="replace")
    except Exception:
        version = banner[:50]
    if version:
        return [_f(ip, port, f"MySQL: {version}", Severity.INFO, f"MySQL version: {version}")]
    return []


async def _check_postgresql(ip: str, port: int) -> list[Finding]:
    user = b"postgres"
    startup = b'\x00\x03\x00\x00' + b'user\x00' + user + b'\x00database\x00postgres\x00\x00'
    length = struct.pack(">I", len(startup) + 4)
    resp = await _tcp_send_recv(ip, port, length + startup)
    if not resp:
        return []
    if resp[0:1] == b'R' and len(resp) >= 9:
        auth_type = struct.unpack(">I", resp[5:9])[0]
        if auth_type == 0:
            return [_f(ip, port, "PostgreSQL: No Password Required (trust auth)", Severity.CRITICAL,
                       "PostgreSQL allows login as 'postgres' without password. Full DB access.")]
        elif auth_type == 3:
            return [_f(ip, port, "PostgreSQL: Cleartext Password Auth", Severity.MEDIUM,
                       "PostgreSQL uses cleartext password authentication (insecure).")]
        elif auth_type == 5:
            return [_f(ip, port, "PostgreSQL: MD5 Auth", Severity.INFO, "PostgreSQL uses MD5 auth.")]
        elif auth_type == 10:
            return [_f(ip, port, "PostgreSQL: SCRAM-SHA-256 Auth", Severity.INFO, "Secure auth.")]
    return []


async def _check_smtp(ip: str, port: int) -> list[Finding]:
    findings: list[Finding] = []
    conn = await _tcp_connect(ip, port)
    if not conn:
        return []
    reader, writer = conn
    try:
        banner = (await asyncio.wait_for(reader.read(1024), timeout=_TIMEOUT)).decode(errors="replace").strip()
        findings.append(_f(ip, port, f"SMTP: {banner[:60]}", Severity.INFO, banner))
        writer.write(b"EHLO test\r\n")
        await writer.drain()
        ehlo = (await asyncio.wait_for(reader.read(2048), timeout=_TIMEOUT)).decode(errors="replace")
        if "VRFY" in ehlo:
            findings.append(_f(ip, port, "SMTP: VRFY Supported (user enumeration)", Severity.MEDIUM,
                               "SMTP supports VRFY command.", ehlo))
        if "EXPN" in ehlo:
            findings.append(_f(ip, port, "SMTP: EXPN Supported (list enumeration)", Severity.MEDIUM,
                               "SMTP supports EXPN command.", ehlo))
    except Exception:
        pass
    finally:
        writer.close()
    return findings


async def _check_vnc(ip: str, port: int) -> list[Finding]:
    banner = await _tcp_banner(ip, port)
    if not banner or "RFB" not in banner:
        return []
    findings = [_f(ip, port, f"VNC: {banner[:30]}", Severity.INFO, f"VNC: {banner}")]
    conn = await _tcp_connect(ip, port)
    if conn:
        reader, writer = conn
        try:
            ver = await asyncio.wait_for(reader.read(12), timeout=_TIMEOUT)
            writer.write(ver)
            await writer.drain()
            auth = await asyncio.wait_for(reader.read(256), timeout=_TIMEOUT)
            if auth and len(auth) > 1 and auth[0] > 0 and 1 in auth[1:1 + auth[0]]:
                findings.append(_f(ip, port, "VNC: No Authentication Required", Severity.CRITICAL,
                                   "VNC allows connections without password. Full remote desktop."))
        except Exception:
            pass
        finally:
            writer.close()
    return findings


async def _check_rdp(ip: str, port: int) -> list[Finding]:
    conn = await _tcp_connect(ip, port)
    if conn:
        conn[1].close()
        return [_f(ip, port, "RDP: Service Detected", Severity.INFO,
                   f"RDP accepting connections on port {port}.")]
    return []


async def _check_memcached(ip: str, port: int) -> list[Finding]:
    resp = await _tcp_send_recv(ip, port, b"stats\r\n", 4096)
    if resp and b"STAT" in resp:
        return [_f(ip, port, "Memcached: No Authentication", Severity.HIGH,
                   "Memcached accepts commands without auth. Data exposure risk.",
                   resp.decode(errors="replace")[:1000])]
    return []


async def _check_elasticsearch(ip: str, port: int) -> list[Finding]:
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(f"http://{ip}:{port}/", timeout=aiohttp.ClientTimeout(total=_TIMEOUT)) as r:
                if r.status == 200:
                    body = await r.text()
                    if "cluster_name" in body or "tagline" in body:
                        return [_f(ip, port, "Elasticsearch: No Authentication", Severity.HIGH,
                                   "Elasticsearch API accessible without auth.", body[:500])]
    except Exception:
        pass
    return []


async def _check_docker(ip: str, port: int) -> list[Finding]:
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(f"http://{ip}:{port}/version", timeout=aiohttp.ClientTimeout(total=_TIMEOUT)) as r:
                if r.status == 200:
                    body = await r.text()
                    if "ApiVersion" in body or "Version" in body:
                        return [_f(ip, port, "Docker: Unauthenticated API", Severity.CRITICAL,
                                   "Docker API without auth. Container escape → host RCE.", body[:500])]
    except Exception:
        pass
    return []


async def _check_telnet(ip: str, port: int) -> list[Finding]:
    banner = await _tcp_banner(ip, port)
    if banner:
        return [_f(ip, port, f"Telnet: {banner[:60]}", Severity.MEDIUM,
                   f"Telnet (cleartext protocol).\nBanner: {banner}")]
    return []


async def _check_ldap(ip: str, port: int) -> list[Finding]:
    bind_req = (
        b'\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00'
    )
    resp = await _tcp_send_recv(ip, port, bind_req)
    if resp and len(resp) > 10:
        if b'\x0a\x01\x00' in resp:
            return [_f(ip, port, "LDAP: Anonymous Bind Allowed", Severity.HIGH,
                       "LDAP allows anonymous bind. Directory data accessible.")]
        return [_f(ip, port, "LDAP: Service Detected", Severity.INFO, "LDAP responding.")]
    return []


# ── Router ───────────────────────────────────────────────

_CHECKS: dict[str, object] = {
    "ssh": _check_ssh,
    "ftp": _check_ftp,
    "microsoft-ds": _check_ldap,
    "netbios-ssn": _check_ldap,
    "mysql": _check_mysql,
    "ms-sql-s": _check_mysql,
    "postgresql": _check_postgresql,
    "mongodb": _check_mongodb,
    "redis": _check_redis,
    "ldap": _check_ldap,
    "ms-wbt-server": _check_rdp,
    "vnc": _check_vnc,
    "smtp": _check_smtp,
    "telnet": _check_telnet,
    "memcached": _check_memcached,
}

# Well-known ports for services that nmap might not name correctly
_PORT_CHECKS: dict[int, object] = {
    6379: _check_redis,
    27017: _check_mongodb,
    11211: _check_memcached,
    9200: _check_elasticsearch,
    2375: _check_docker,
    2376: _check_docker,
}


async def enumerate_services(
    host: Host, config: ScanConfig, tree: OutputTree, sem: asyncio.Semaphore,
) -> list[Finding]:
    """Pure Python service enumeration. No brute force."""
    async with sem:
        if not host.open_ports:
            return []

        tasks: list[asyncio.Task] = []
        checked: set[int] = set()

        for port in host.open_ports:
            svc = port.service_name
            # Skip HTTP — already covered by nuclei + httpx
            if svc in ("http", "https", "http-proxy", "http-alt"):
                # But check well-known ports
                if port.number in _PORT_CHECKS:
                    tasks.append(asyncio.create_task(_PORT_CHECKS[port.number](host.ip, port.number)))
                    checked.add(port.number)
                continue

            fn = _CHECKS.get(svc)
            if fn and port.number not in checked:
                tasks.append(asyncio.create_task(fn(host.ip, port.number)))
                checked.add(port.number)

            # Also check by well-known port
            if port.number in _PORT_CHECKS and port.number not in checked:
                tasks.append(asyncio.create_task(_PORT_CHECKS[port.number](host.ip, port.number)))
                checked.add(port.number)

        if not tasks:
            return []

        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_findings: list[Finding] = []
        for r in results:
            if isinstance(r, list):
                all_findings.extend(r)
        log.info("Service enum %s: %d finding(s)", host.ip, len(all_findings))
        return all_findings
