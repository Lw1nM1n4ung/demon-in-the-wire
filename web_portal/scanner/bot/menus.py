from __future__ import annotations

from telegram import InlineKeyboardButton, InlineKeyboardMarkup

PAGE_SIZE = 5


def main_menu_kb(role: str = 'viewer') -> InlineKeyboardMarkup:
    rows = [
        [
            InlineKeyboardButton('📊 Dashboard', callback_data='mn:dash'),
            InlineKeyboardButton('🔍 Scans', callback_data='sl:0'),
        ],
        [
            InlineKeyboardButton('🛡 Findings', callback_data='fl:all:0'),
            InlineKeyboardButton('💻 Assets', callback_data='al:0'),
        ],
    ]
    if role in ('engineer', 'owner'):
        rows.append([
            InlineKeyboardButton('📅 Schedules', callback_data='cl:0'),
            InlineKeyboardButton('➕ New Scan', callback_data='ns:pick'),
        ])
    if role == 'owner':
        rows.append([
            InlineKeyboardButton('🏥 Health', callback_data='hl'),
            InlineKeyboardButton('⚙️ Config', callback_data='cf'),
        ])
    return InlineKeyboardMarkup(rows)


def scan_list_kb(scans: list, page: int, total_pages: int) -> InlineKeyboardMarkup:
    rows = []
    from scanner.bot.formatting import short_id, status_icon
    for sid, target, status, *_ in scans:
        icon = status_icon(status)
        label = f'{icon} {target[:28]}'
        rows.append([InlineKeyboardButton(label, callback_data=f'sd:{short_id(sid)}')])
    rows.append(_pagination_row('sl', page, total_pages))
    rows.append([InlineKeyboardButton('⬅ Menu', callback_data='mn')])
    return InlineKeyboardMarkup(rows)


def scan_detail_kb(sid: str, status: str, has_screenshots: bool = False) -> InlineKeyboardMarkup:
    row1 = [InlineKeyboardButton('🛡 Findings', callback_data=f'sf:{sid}:0')]
    if has_screenshots:
        row1.append(InlineKeyboardButton('📷 Screenshots', callback_data=f'sp:{sid}:0'))
    row2 = []
    if status == 'completed':
        row2.append(InlineKeyboardButton('📄 Report', callback_data=f'sr:{sid}'))
    if status in ('running', 'pending'):
        row2.append(InlineKeyboardButton('❌ Cancel', callback_data=f'sx:{sid}'))
    rows = [row1]
    if row2:
        rows.append(row2)
    rows.append([InlineKeyboardButton('⬅ Scans', callback_data='sl:0')])
    return InlineKeyboardMarkup(rows)


def finding_filter_kb(scan_sid: str | None = None) -> InlineKeyboardMarkup:
    prefix = f'sf:{scan_sid}:0' if scan_sid else 'fl'
    rows = [
        [
            InlineKeyboardButton('🔴 Critical', callback_data=f'{prefix}:critical' if scan_sid else 'fl:critical:0'),
            InlineKeyboardButton('🟠 High', callback_data=f'{prefix}:high' if scan_sid else 'fl:high:0'),
        ],
        [
            InlineKeyboardButton('🟡 Medium', callback_data=f'{prefix}:medium' if scan_sid else 'fl:medium:0'),
            InlineKeyboardButton('🔵 Low', callback_data=f'{prefix}:low' if scan_sid else 'fl:low:0'),
        ],
        [InlineKeyboardButton('📋 All', callback_data=f'{prefix}' if scan_sid else 'fl:all:0')],
    ]
    back = f'sd:{scan_sid}' if scan_sid else 'mn'
    rows.append([InlineKeyboardButton('⬅ Back', callback_data=back)])
    return InlineKeyboardMarkup(rows)


def findings_list_kb(page: int, total_pages: int, severity: str = 'all',
                     scan_sid: str | None = None) -> InlineKeyboardMarkup:
    rows = []
    if scan_sid:
        prefix = f'sf:{scan_sid}'
        rows.append(_pagination_row_ext(prefix, page, total_pages, severity))
        rows.append([InlineKeyboardButton('⬅ Back', callback_data=f'sd:{scan_sid}')])
    else:
        prefix = 'fl'
        rows.append(_pagination_row_ext(prefix, page, total_pages, severity))
        rows.append([InlineKeyboardButton('⬅ Menu', callback_data='mn')])
    return InlineKeyboardMarkup(rows)


def asset_list_kb(page: int, total_pages: int) -> InlineKeyboardMarkup:
    rows = [
        _pagination_row('al', page, total_pages),
        [InlineKeyboardButton('⬅ Menu', callback_data='mn')],
    ]
    return InlineKeyboardMarkup(rows)


def asset_detail_kb(asset_sid: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton('⬅ Assets', callback_data='al:0')],
    ])


def schedule_list_kb(schedules: list, page: int, total_pages: int) -> InlineKeyboardMarkup:
    rows = []
    from scanner.bot.formatting import short_id
    for sid, name, target, enabled, *_ in schedules:
        icon = '✅' if enabled else '⏸'
        label = f'{icon} {target[:28]}'
        rows.append([
            InlineKeyboardButton(label, callback_data=f'cd:{short_id(sid)}'),
            InlineKeyboardButton('🔄', callback_data=f'ct:{short_id(sid)}'),
        ])
    rows.append(_pagination_row('cl', page, total_pages))
    rows.append([InlineKeyboardButton('⬅ Menu', callback_data='mn')])
    return InlineKeyboardMarkup(rows)


def schedule_detail_kb(sid: str, enabled: bool) -> InlineKeyboardMarkup:
    toggle_label = '⏸ Disable' if enabled else '✅ Enable'
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton(toggle_label, callback_data=f'ct:{sid}'),
            InlineKeyboardButton('▶️ Run Now', callback_data=f'cr:{sid}'),
        ],
        [InlineKeyboardButton('⬅ Schedules', callback_data='cl:0')],
    ])


def photo_list_kb(sid: str, count: int, page: int, total_pages: int) -> InlineKeyboardMarkup:
    rows = []
    if count > 0:
        rows.append([InlineKeyboardButton(f'📷 Send All ({count})', callback_data=f'sp:{sid}:all')])
    rows.append(_pagination_row_ext(f'sp:{sid}', page, total_pages, ''))
    rows.append([InlineKeyboardButton('⬅ Back', callback_data=f'sd:{sid}')])
    return InlineKeyboardMarkup(rows)


def new_scan_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton('🔍 Full', callback_data='ns:full'),
            InlineKeyboardButton('⚡ Quick', callback_data='ns:quick'),
        ],
        [
            InlineKeyboardButton('🔌 Port', callback_data='ns:port'),
            InlineKeyboardButton('🌐 Web', callback_data='ns:web'),
        ],
        [InlineKeyboardButton('🔧 Service', callback_data='ns:service')],
        [InlineKeyboardButton('⬅ Menu', callback_data='mn')],
    ])


def confirm_cancel_kb(sid: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton('✅ Yes, cancel', callback_data=f'sxc:{sid}'),
            InlineKeyboardButton('❌ No', callback_data=f'sd:{sid}'),
        ],
    ])


def _pagination_row(prefix: str, page: int, total_pages: int) -> list[InlineKeyboardButton]:
    buttons = []
    if page > 0:
        buttons.append(InlineKeyboardButton('◀', callback_data=f'{prefix}:{page - 1}'))
    buttons.append(InlineKeyboardButton(f'{page + 1}/{total_pages}', callback_data='noop'))
    if page < total_pages - 1:
        buttons.append(InlineKeyboardButton('▶', callback_data=f'{prefix}:{page + 1}'))
    return buttons


def _pagination_row_ext(prefix: str, page: int, total_pages: int, extra: str) -> list[InlineKeyboardButton]:
    suffix = f':{extra}' if extra else ''
    buttons = []
    if page > 0:
        buttons.append(InlineKeyboardButton('◀', callback_data=f'{prefix}:{page - 1}{suffix}'))
    buttons.append(InlineKeyboardButton(f'{page + 1}/{total_pages}', callback_data='noop'))
    if page < total_pages - 1:
        buttons.append(InlineKeyboardButton('▶', callback_data=f'{prefix}:{page + 1}{suffix}'))
    return buttons
