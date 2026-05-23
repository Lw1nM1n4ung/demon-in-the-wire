"""Match scan results against Metasploit Framework module metadata.

Loads modules_metadata_base.json (downloaded at Docker build time) and builds
three lookup indexes for confidence-tiered matching:
  HIGH   — Finding CVE matches a module's references
  MEDIUM — service_product token + port number match
  LOW    — port + service_name match (restricted service list, never http/https)
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

MSF_JSON_PATH = Path('/opt/metasploit-framework/embedded/framework/db/modules_metadata_base.json')

_cve_index: dict[str, list[dict]] | None = None
_product_index: dict[str, list[dict]] | None = None
_port_index: dict[int, list[dict]] | None = None

LOW_MATCH_SERVICES = frozenset({
    'ssh', 'ftp', 'smb', 'mysql', 'postgresql', 'postgres',
    'redis', 'vnc', 'rdp', 'telnet', 'snmp', 'smtp', 'pop3',
    'imap', 'mssql', 'ms-sql-s', 'oracle', 'mongodb', 'memcached',
    'rsync', 'nfs', 'rpc', 'ldap', 'kerberos',
})

RANK_NAMES = {
    0: 'Manual', 100: 'Low', 200: 'Average',
    300: 'Normal', 400: 'Good', 500: 'Great', 600: 'Excellent',
}


def _slim_module(mod: dict) -> dict:
    """Extract only the fields we need for display/storage."""
    refs = mod.get('references') or []
    cves = [r for r in refs if r.startswith('CVE-')]
    rank = mod.get('rank', 0)
    return {
        'module_fullname': mod.get('fullname', ''),
        'module_name': mod.get('name', ''),
        'module_type': mod.get('type', ''),
        'module_rank': rank,
        'module_rank_name': RANK_NAMES.get(rank, str(rank)),
        'disclosure_date': mod.get('disclosure_date') or '',
        'description': (mod.get('description') or '')[:500],
        'references': cves,
        'rport': mod.get('rport'),
        'platform': mod.get('platform', ''),
    }


def _build_indexes() -> None:
    global _cve_index, _product_index, _port_index

    if not MSF_JSON_PATH.exists():
        logger.warning('MSF metadata not found at %s — exploit matching disabled', MSF_JSON_PATH)
        _cve_index, _product_index, _port_index = {}, {}, {}
        return

    logger.info('Loading MSF metadata from %s', MSF_JSON_PATH)
    with open(MSF_JSON_PATH) as f:
        raw = json.load(f)

    cve_idx: dict[str, list[dict]] = {}
    product_idx: dict[str, list[dict]] = {}
    port_idx: dict[int, list[dict]] = {}

    for mod in raw.values():
        mod_type = mod.get('type', '')
        refs = mod.get('references') or []
        has_cve = any(r.startswith('CVE-') for r in refs)

        if mod_type == 'exploit':
            pass
        elif mod_type == 'auxiliary' and has_cve:
            pass
        else:
            continue

        slim = _slim_module(mod)

        for ref in refs:
            if ref.startswith('CVE-'):
                cve_idx.setdefault(ref, []).append(slim)

        name_lower = (mod.get('name') or '').lower()
        fullname_lower = (mod.get('fullname') or '').lower()
        combined_text = name_lower + ' ' + fullname_lower

        tokens = set(re.findall(r'[a-z][a-z0-9_]{2,}', combined_text))
        for token in tokens:
            product_idx.setdefault(token, []).append(slim)

        rport = mod.get('rport')
        if rport and isinstance(rport, int):
            port_idx.setdefault(rport, []).append(slim)

        for p in (mod.get('autofilter_ports') or []):
            if isinstance(p, int) and p != rport:
                port_idx.setdefault(p, []).append(slim)

    _cve_index = cve_idx
    _product_index = product_idx
    _port_index = port_idx
    logger.info(
        'MSF indexes built: %d CVEs, %d product tokens, %d ports',
        len(cve_idx), len(product_idx), len(port_idx),
    )


def _ensure_indexes() -> None:
    if _cve_index is None:
        _build_indexes()


def match_exploits(ports: list[dict], findings: list[dict]) -> list[dict]:
    """Match scan ports/findings against MSF modules.

    Args:
        ports: list of dicts with keys: number, service_name, service_product,
               service_version, host_ip (optional)
        findings: list of dicts with keys: cve (comma-separated string),
                  host_ip (optional), port (optional)

    Returns:
        list of match dicts with: module_fullname, module_name, confidence,
        match_reason, module_rank, module_type, disclosure_date, description,
        references, host_ip, port_number
    """
    _ensure_indexes()
    if not _cve_index and not _product_index and not _port_index:
        return []

    results: list[dict] = []
    seen: set[tuple] = set()

    def _add(slim: dict, confidence: str, reason: str, host_ip: str, port_num: int | None):
        key = (slim['module_fullname'], host_ip, port_num)
        if key in seen:
            return
        seen.add(key)
        results.append({
            **slim,
            'confidence': confidence,
            'match_reason': reason,
            'host_ip': host_ip or '',
            'port_number': port_num,
        })

    for f in findings:
        cve_str = f.get('cve') or ''
        cves = [c.strip() for c in cve_str.split(',') if c.strip()]
        host_ip = f.get('host_ip', '')
        f_port = f.get('port')
        port_num = int(f_port) if f_port and str(f_port).isdigit() else None

        for cve in cves:
            if not cve.startswith('CVE-'):
                continue
            for slim in (_cve_index or {}).get(cve, []):
                _add(slim, 'high', f'CVE match: {cve}', host_ip, port_num)

    for p in ports:
        port_num = p.get('number')
        service_name = (p.get('service_name') or '').lower().strip()
        service_product = (p.get('service_product') or '').lower().strip()
        host_ip = p.get('host_ip', '')

        if service_product and service_product not in ('unknown', ''):
            product_tokens = set(re.findall(r'[a-z][a-z0-9_]{2,}', service_product))
            for token in product_tokens:
                for slim in (_product_index or {}).get(token, []):
                    mod_rport = slim.get('rport')
                    if mod_rport and mod_rport == port_num:
                        reason = f'Product "{service_product}" + port {port_num}'
                        _add(slim, 'medium', reason, host_ip, port_num)

        if service_name in LOW_MATCH_SERVICES and port_num:
            for slim in (_port_index or {}).get(port_num, []):
                fullname = slim.get('module_fullname', '').lower()
                if service_name in fullname:
                    reason = f'Service {service_name} on port {port_num}'
                    _add(slim, 'low', reason, host_ip, port_num)

    results.sort(key=lambda m: (
        {'high': 0, 'medium': 1, 'low': 2}.get(m['confidence'], 3),
        -m.get('module_rank', 0),
    ))

    return results
