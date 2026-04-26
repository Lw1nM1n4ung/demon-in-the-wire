from __future__ import annotations

import psutil
from asgiref.sync import sync_to_async
from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from scanner.bot.formatting import esc, format_duration, progress_bar
from scanner.models import SiteConfig, User

HTML = 'HTML'


async def handle_health(query, user, rest, context):
    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    uptime = int(psutil.boot_time())
    from django.utils import timezone as dj_tz
    import datetime
    up_secs = int((dj_tz.now() - datetime.datetime.fromtimestamp(uptime, tz=datetime.timezone.utc)).total_seconds())

    lines = [
        '<b>🏥 System Health</b>',
        '━━━━━━━━━━━━━━━',
        '',
        f'<b>CPU:</b>  {progress_bar(cpu, 100)} {cpu:.0f}%',
        f'<b>RAM:</b>  {progress_bar(mem.percent, 100)} {mem.percent:.0f}% ({mem.used // (1024**3)}/{mem.total // (1024**3)} GB)',
        f'<b>Disk:</b> {progress_bar(disk.percent, 100)} {disk.percent:.0f}% ({disk.used // (1024**3)}/{disk.total // (1024**3)} GB)',
        f'<b>Uptime:</b> {format_duration(up_secs)}',
    ]

    kb = InlineKeyboardMarkup([
        [
            InlineKeyboardButton('🔄 Refresh', callback_data='hl'),
            InlineKeyboardButton('⚙️ Config', callback_data='cf'),
        ],
        [InlineKeyboardButton('⬅ Menu', callback_data='mn')],
    ])
    await query.edit_message_text('\n'.join(lines), reply_markup=kb, parse_mode=HTML)


async def handle_config(query, user, rest, context):
    def _q():
        cfg = SiteConfig.get()
        user_count = User.objects.filter(is_active=True).count()
        return cfg, user_count

    cfg, user_count = await sync_to_async(_q)()

    lines = [
        '<b>⚙️ Site Config</b>',
        '━━━━━━━━━━━━━',
        '',
        '<b>Scan Defaults</b>',
        f'  Parallelism: {cfg.default_parallelism}',
        f'  Timeout: {format_duration(cfg.default_timeout)}',
        f'  Report formats: {esc(cfg.default_report_formats or "dashboard,html,docx")}',
        '',
        '<b>System</b>',
        f'  Timezone: {esc(cfg.schedule_timezone)}',
        f'  Active users: {user_count}',
        f'  Setup complete: {"✅" if cfg.setup_complete else "❌"}',
        '',
        '<b>Telegram</b>',
        f'  Bot token: {"✅ Set" if cfg.telegram_bot_token else "❌ Not set"}',
        f'  Shared chat: {"✅ Set" if cfg.telegram_shared_chat_id else "❌ Not set"}',
    ]

    kb = InlineKeyboardMarkup([
        [
            InlineKeyboardButton('🏥 Health', callback_data='hl'),
            InlineKeyboardButton('🔄 Refresh', callback_data='cf'),
        ],
        [InlineKeyboardButton('⬅ Menu', callback_data='mn')],
    ])
    await query.edit_message_text('\n'.join(lines), reply_markup=kb, parse_mode=HTML)
