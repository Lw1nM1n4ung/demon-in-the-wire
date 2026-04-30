"""GitHub release checker and feed updater for Wire_Ghost."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from datetime import datetime, timezone as tz
from pathlib import Path

from django.core.cache import cache

log = logging.getLogger('scanner.update_check')

GITHUB_REPO = 'Lw1nM1n4ung/demon-in-the-wire'
GITHUB_API_URL = f'https://api.github.com/repos/{GITHUB_REPO}/releases/latest'
CACHE_KEY = 'wg:update:check_result'
CACHE_TTL = 6 * 3600
FLAG_DIR = Path('/app/logs')


def _now_iso() -> str:
    return datetime.now(tz.utc).isoformat()


def _current_version() -> str:
    try:
        from wireghost import __version__
        return __version__
    except ImportError:
        return '0.0.0'


def check_latest_release(*, force: bool = False) -> dict:
    if not force:
        cached = cache.get(CACHE_KEY)
        if cached:
            return cached

    current = _current_version()
    result = {
        'current': current,
        'latest': None,
        'latest_url': None,
        'release_notes': None,
        'published_at': None,
        'update_available': False,
        'error': None,
        'checked_at': _now_iso(),
    }

    try:
        req = urllib.request.Request(
            GITHUB_API_URL,
            headers={'User-Agent': 'wireghost', 'Accept': 'application/vnd.github+json'},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        tag = (data.get('tag_name') or '').lstrip('v')
        if not tag:
            result['error'] = 'No tag_name in release'
            cache.set(CACHE_KEY, result, CACHE_TTL)
            return result

        result['latest'] = tag
        result['latest_url'] = data.get('html_url', '')
        result['release_notes'] = (data.get('body') or '')[:2000]
        result['published_at'] = data.get('published_at', '')

        try:
            from packaging.version import Version, InvalidVersion
            try:
                result['update_available'] = Version(tag) > Version(current)
            except InvalidVersion:
                result['update_available'] = tag != current
        except ImportError:
            result['update_available'] = tag != current

    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as e:
        result['error'] = str(e)
        log.info('GitHub release check failed: %s', e)

    cache.set(CACHE_KEY, result, CACHE_TTL)
    return result


def write_update_flag(requested_by: str) -> dict:
    flag_path = FLAG_DIR / 'update-requested.json'
    try:
        flag_path.parent.mkdir(parents=True, exist_ok=True)
        flag_data = {
            'requested_at': _now_iso(),
            'requested_by': requested_by,
            'target_version': (check_latest_release() or {}).get('latest', 'unknown'),
        }
        flag_path.write_text(json.dumps(flag_data, indent=2))
    except OSError as e:
        log.warning('Failed to write update flag: %s', e)
        return {'status': 'error', 'error': str(e)}
    return {
        'status': 'flagged',
        'flag_path': 'logs/api/update-requested.json',
        'command': './scripts/wg-ctl update',
    }


def read_update_status() -> dict | None:
    status_path = FLAG_DIR / 'update-status.json'
    if not status_path.exists():
        return None
    try:
        return json.loads(status_path.read_text())
    except (OSError, ValueError):
        return None


def run_feed_update() -> dict:
    import shutil
    import subprocess

    updated = []
    errors = []

    if shutil.which('nuclei'):
        try:
            r = subprocess.run(
                ['nuclei', '-update-templates'],
                capture_output=True, text=True, timeout=120,
            )
            if r.returncode == 0:
                updated.append('nuclei-templates')
            else:
                errors.append(f'nuclei: exit {r.returncode}')
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            errors.append(f'nuclei: {e}')

    if shutil.which('searchsploit'):
        try:
            r = subprocess.run(
                ['searchsploit', '-u'],
                capture_output=True, text=True, timeout=120,
            )
            if r.returncode == 0:
                updated.append('searchsploit-db')
            else:
                errors.append(f'searchsploit: exit {r.returncode}')
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            errors.append(f'searchsploit: {e}')

    if shutil.which('greenbone-feed-sync'):
        try:
            r = subprocess.run(
                ['greenbone-feed-sync', '--type', 'nasl'],
                capture_output=True, text=True, timeout=600,
            )
            if r.returncode == 0:
                updated.append('openvas-nasl')
            else:
                errors.append(f'greenbone-feed-sync: exit {r.returncode}')
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            errors.append(f'greenbone-feed-sync: {e}')

    status = 'completed' if not errors else ('partial' if updated else 'failed')
    return {'status': status, 'updated': updated, 'errors': errors}
