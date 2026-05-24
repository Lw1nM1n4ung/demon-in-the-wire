from __future__ import annotations

import html as _html
from typing import Optional

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "ℹ️",
}

_STATUS_ICON = {
    "completed": "✅",
    "running": "🔄",
    "failed": "❌",
    "cancelled": "⏸",
    "pending": "⏳",
}


def esc(text) -> str:
    return _html.escape(str(text))


def severity_emoji(severity: str) -> str:
    return _SEVERITY_EMOJI.get(severity.lower(), "")


def severity_line(*, critical: int = 0, high: int = 0, medium: int = 0, low: int = 0) -> str:
    parts = []
    if critical:
        parts.append(f"🔴 {critical}")
    if high:
        parts.append(f"🟠 {high}")
    if medium:
        parts.append(f"🟡 {medium}")
    if low:
        parts.append(f"🔵 {low}")
    return "  ".join(parts)


def short_id(uuid_str) -> str:
    return str(uuid_str)[:8]


def status_icon(status: str) -> str:
    return _STATUS_ICON.get(status, "❓")


def truncate_list(items: list, limit: int = 10) -> tuple[list, int]:
    if len(items) <= limit:
        return items, 0
    return items[:limit], len(items) - limit


def format_duration(seconds: Optional[int]) -> str:
    if seconds is None:
        return "—"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours, mins = divmod(minutes, 60)
    return f"{hours}h {mins}m {secs}s"


def time_ago(dt) -> str:
    if not dt:
        return "—"
    from django.utils import timezone as dj_tz

    delta = dj_tz.now() - dt
    secs = int(delta.total_seconds())
    if secs < 0:
        return "just now"
    if secs < 60:
        return f"{secs}s ago"
    mins = secs // 60
    if mins < 60:
        return f"{mins}m ago"
    hours = mins // 60
    if hours < 24:
        return f"{hours}h ago"
    days = hours // 24
    return f"{days}d ago"


def progress_bar(done, total, width: int = 10) -> str:
    if total == 0:
        return "░" * width
    filled = round(done / total * width)
    return "▓" * filled + "░" * (width - filled)


SEPARATOR = "━━━━━━━━━━━━━━━━━━"


def header(emoji: str, title: str) -> str:
    return f"<b>{emoji} {esc(title)}</b>\n{SEPARATOR}"


def section(emoji: str, title: str) -> str:
    return f"\n<b>{emoji} {title}</b>"
