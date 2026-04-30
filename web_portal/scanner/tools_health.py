"""Live probe of external scan tools on the api container's PATH.

Drives the Settings → Tools tab. Runs `which <binary>` + a truncated
`<binary> <version-arg>` for each whitelisted tool, aggregates the result,
and caches it for 30 s to avoid fork storms when multiple clients poll.

SECURITY NOTE: tool names + args are hardcoded in TOOLS below — we never
execute anything the client sends us.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import List

from django.core.cache import cache

CACHE_KEY = 'scanner.tools_health.v1'
CACHE_TTL = 30  # seconds

# (display name, binary, version-flag args). Every tool Wire_Ghost knows how
# to drive from the pipeline. Add entries here; don't expose this list for
# user configuration.
TOOLS = [
    ('Nmap',         'nmap',         ['-V']),
    ('Nuclei',       'nuclei',       ['-version']),
    ('Naabu',        'naabu',        ['-version']),
    ('Masscan',      'masscan',      ['--version']),
    ('httpx',        'httpx',        ['-version']),
    ('fping',        'fping',        ['-v']),
    ('Searchsploit', 'searchsploit', ['--version']),
    ('WPScan',       'wpscan',       ['--version']),
    ('scannerctl',   'scannerctl',   ['--version']),
    ('enum4linux',   'enum4linux',   ['-h']),
]


def _extract_version(output: str) -> str:
    """Best-effort extraction of a version string from tool output."""
    if not output:
        return ''
    # Grab the first non-empty line, trim, cap length for display.
    for line in output.splitlines():
        line = line.strip()
        if line:
            return line[:120]
    return ''


def _probe_one(binary: str, version_args: list) -> dict:
    path = shutil.which(binary)
    if not path:
        return {'path': '', 'version': '', 'ok': False}
    try:
        res = subprocess.run(
            [path, *version_args],
            capture_output=True, text=True, timeout=2,
        )
        # Many tools emit version on stderr; union both streams.
        combined = (res.stdout or '') + (res.stderr or '')
        return {'path': path, 'version': _extract_version(combined), 'ok': True}
    except (subprocess.TimeoutExpired, OSError, ValueError):
        # Binary exists but didn't respond — count as present but broken.
        return {'path': path, 'version': '(no response)', 'ok': True}


def probe_all(*, refresh: bool = False) -> List[dict]:
    """Return one dict per tool: {name, binary, path, version, ok}.

    Cached for 30 s. Pass ``refresh=True`` to force a re-probe.
    """
    if not refresh:
        cached = cache.get(CACHE_KEY)
        if cached is not None:
            return cached

    results = []
    for name, binary, args in TOOLS:
        info = _probe_one(binary, args)
        results.append({
            'name': name,
            'binary': binary,
            **info,
        })

    cache.set(CACHE_KEY, results, CACHE_TTL)
    return results
