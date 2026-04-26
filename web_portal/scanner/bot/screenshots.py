from __future__ import annotations

import logging
from pathlib import Path

from telegram import InputMediaPhoto

log = logging.getLogger('scanner.bot')

PHOTO_SIZE_LIMIT = 5 * 1024 * 1024
ALBUM_MAX = 10


def resolve_path(screenshot) -> Path | None:
    scan_dir = screenshot.scan.output_dir
    if not scan_dir:
        return None
    root = Path(scan_dir).resolve()
    img = (Path(scan_dir) / screenshot.filename).resolve()
    if not img.is_relative_to(root):
        log.warning('Path traversal blocked: %s (root: %s)', img, root)
        return None
    if not img.exists():
        return None
    return img


async def send_one(bot, chat_id: int, screenshot, caption: str = '') -> bool:
    path = resolve_path(screenshot)
    if not path:
        return False
    try:
        with open(path, 'rb') as f:
            if path.stat().st_size > PHOTO_SIZE_LIMIT:
                await bot.send_document(
                    chat_id=chat_id, document=f,
                    caption=caption[:1024] if caption else None,
                    parse_mode='HTML',
                )
            else:
                await bot.send_photo(
                    chat_id=chat_id, photo=f,
                    caption=caption[:1024] if caption else None,
                    parse_mode='HTML',
                )
        return True
    except Exception:
        log.exception('Failed to send screenshot %s', screenshot.id)
        return False


async def send_album(bot, chat_id: int, screenshots: list, label: str = '') -> int:
    media = []
    files = []
    try:
        for i, ss in enumerate(screenshots[:ALBUM_MAX]):
            path = resolve_path(ss)
            if not path or path.stat().st_size > PHOTO_SIZE_LIMIT:
                continue
            f = open(path, 'rb')
            files.append(f)
            caption = ''
            if i == 0 and label:
                caption = f'📷 <b>{label}</b> ({len(screenshots)} screenshot{"s" if len(screenshots) != 1 else ""})'
            media.append(InputMediaPhoto(
                media=f,
                caption=caption or None,
                parse_mode='HTML' if caption else None,
            ))
        if not media:
            return 0
        await bot.send_media_group(chat_id=chat_id, media=media)
        return len(media)
    except Exception:
        log.exception('Failed to send screenshot album')
        return 0
    finally:
        for f in files:
            f.close()


async def send_report_file(bot, chat_id: int, report) -> bool:
    path = Path(report.file_path).resolve()
    if not path.exists():
        return False
    from django.conf import settings
    allowed = Path(getattr(settings, 'REPORT_OUTPUT_DIR', '/opt/wireghost/reports')).resolve()
    if not path.is_relative_to(allowed):
        log.warning('Report path outside allowed directory: %s', path)
        return False
    fmt = report.format.upper()
    size_mb = path.stat().st_size / (1024 * 1024)
    caption = f'📄 <b>{fmt} Report</b> — {size_mb:.1f} MB'
    try:
        with open(path, 'rb') as f:
            await bot.send_document(
                chat_id=chat_id, document=f,
                caption=caption, parse_mode='HTML',
                filename=path.name,
            )
        return True
    except Exception:
        log.exception('Failed to send report file %s', report.id)
        return False
