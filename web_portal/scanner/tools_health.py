"""Live probe of external scan tools — dispatched to the Celery worker.

Drives the Settings → Tools tab.  The API container runs a slim image
without scan tools, so probing is sent as a Celery task to the worker
(which has nmap, nuclei, etc.).  Results are cached in Redis for 60 s.

SECURITY NOTE: tool names + args are hardcoded in TOOLS below — we never
execute anything the client sends us.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from typing import List

from django.core.cache import cache

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

log = logging.getLogger(__name__)

CACHE_KEY = 'scanner.tools_health.v2'
CACHE_TTL = 60  # seconds

TOOLS = [
    ('Nmap',         'nmap',         ['-V']),
    ('Nuclei',       'nuclei',       ['-version']),
    ('Naabu',        'naabu',        ['-version']),
    ('Masscan',      'masscan',      ['--version']),
    ('httpx',        'httpx',        ['-version']),
    ('fping',        'fping',        ['-v']),
    ('Searchsploit', 'searchsploit', ['-h']),
    ('WPScan',       'wpscan',       ['--version']),
    ('Nikto',         'nikto',        ['-Version']),
    ('NetExec',       'nxc',          ['--version']),
    ('enum4linux',   'enum4linux',   ['-h']),
]


def _extract_version(output: str) -> str:
    if not output:
        return ''
    for line in output.splitlines():
        line = _ANSI_RE.sub('', line).strip()
        if not line or len(line) < 4:
            continue
        if set(line) <= set('_/\\| ()-*.,\t`~^#[]{}'):
            continue
        return line[:120]
    return ''


def _probe_one(binary: str, version_args: list) -> dict:
    path = shutil.which(binary)
    if not path:
        return {'path': '', 'version': '', 'ok': False}
    try:
        res = subprocess.run(
            [path, *version_args],
            capture_output=True, text=True, timeout=5,
        )
        combined = (res.stdout or '') + (res.stderr or '')
        return {'path': path, 'version': _extract_version(combined), 'ok': True}
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return {'path': path, 'version': '(no response)', 'ok': True}


def probe_all_local() -> List[dict]:
    """Probe tools on the local machine (used by the Celery task on the worker)."""
    results = []
    for name, binary, args in TOOLS:
        info = _probe_one(binary, args)
        results.append({'name': name, 'binary': binary, **info})
    return results


DISPATCH_KEY = 'scanner.tools_health.dispatched'


def probe_all(*, refresh: bool = False) -> List[dict]:
    """Return one dict per tool: {name, binary, path, version, ok}.

    Dispatches probing to the Celery worker (where tools are installed).
    Non-blocking: fires the task and returns immediately.  The task writes
    results to cache; subsequent requests pick them up.
    """
    cached = cache.get(CACHE_KEY)
    if cached is not None and not refresh:
        return cached

    already_dispatched = cache.get(DISPATCH_KEY)
    if not already_dispatched:
        from scanner.tasks import probe_tools_on_worker
        try:
            probe_tools_on_worker.delay()
            cache.set(DISPATCH_KEY, True, 30)
        except Exception as exc:
            log.warning('Failed to dispatch worker probe: %s', exc)

    return cached if cached is not None else []
