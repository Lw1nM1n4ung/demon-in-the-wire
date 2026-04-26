from __future__ import annotations

import re
from typing import Optional

_MDV2_ESCAPE = re.compile(r'([_*\[\]()~`>#\+\-=|{}.!])')

_SEVERITY_EMOJI = {
    'critical': '🔴',
    'high': '🟠',
    'medium': '🟡',
    'low': '🔵',
    'info': 'ℹ️',
}

_STATUS_ICON = {
    'completed': '✅',
    'running': '🔄',
    'failed': '❌',
    'cancelled': '⏸',
    'pending': '⏳',
}


def escape_md(text: str) -> str:
    return _MDV2_ESCAPE.sub(r'\\\1', text)


def severity_emoji(severity: str) -> str:
    return _SEVERITY_EMOJI.get(severity.lower(), '')


def severity_line(*, critical: int = 0, high: int = 0, medium: int = 0, low: int = 0) -> str:
    parts = []
    if critical:
        parts.append(f'🔴 {critical}')
    if high:
        parts.append(f'🟠 {high}')
    if medium:
        parts.append(f'🟡 {medium}')
    if low:
        parts.append(f'🔵 {low}')
    return '  '.join(parts)


def short_id(uuid_str) -> str:
    return str(uuid_str)[:8]


def status_icon(status: str) -> str:
    return _STATUS_ICON.get(status, '❓')


def truncate_list(items: list, limit: int = 10) -> tuple[list, int]:
    if len(items) <= limit:
        return items, 0
    return items[:limit], len(items) - limit


def format_duration(seconds: Optional[int]) -> str:
    if seconds is None:
        return '—'
    seconds = int(seconds)
    if seconds < 60:
        return f'{seconds}s'
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f'{minutes}m {secs}s'
    hours, mins = divmod(minutes, 60)
    return f'{hours}h {mins}m {secs}s'
