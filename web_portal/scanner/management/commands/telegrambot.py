import asyncio
import json
import logging
import os
import threading
import time

import redis
from django.conf import settings
from django.core.management.base import BaseCommand

from telegram import Update
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    MessageHandler,
    filters,
)

from scanner.bot.auth import require_permission
from scanner.bot.callbacks import handle_callback
from scanner.bot.handlers import (
    cmd_assets,
    cmd_cancel,
    cmd_config,
    cmd_findings,
    cmd_health,
    cmd_help,
    cmd_link,
    cmd_menu,
    cmd_newscan,
    cmd_no,
    cmd_report,
    cmd_scan,
    cmd_scans,
    cmd_schedule,
    cmd_start,
    cmd_status,
    cmd_unlink,
    cmd_unlock,
    cmd_users,
    cmd_yes,
    handle_text,
)
from scanner.models import SiteConfig

log = logging.getLogger('scanner.bot')


class Command(BaseCommand):
    help = 'Run the Telegram bot for Wire_Ghost remote control'

    def handle(self, *args, **options):
        while True:
            cfg = SiteConfig.get()
            token = cfg.telegram_bot_token
            if not token:
                self.stderr.write('No Telegram bot token configured. Retrying in 30s…')
                time.sleep(30)
                continue
            break

        self.stdout.write(f'Starting Telegram bot (long-polling)…')

        app = Application.builder().token(token).build()

        # Pre-auth commands (/link must stay ungated for the linking flow)
        app.add_handler(CommandHandler('start', cmd_start))
        app.add_handler(CommandHandler('link', cmd_link))
        app.add_handler(CommandHandler('unlock', cmd_unlock))
        app.add_handler(CommandHandler('yes', cmd_yes))
        app.add_handler(CommandHandler('no', cmd_no))

        # Requires linked account
        app.add_handler(CommandHandler('menu', require_permission('scan:read')(cmd_menu)))
        app.add_handler(CommandHandler('unlink', require_permission('scan:read')(cmd_unlink)))

        # Viewer commands (scan:read)
        app.add_handler(CommandHandler('status', require_permission('scan:read')(cmd_status)))
        app.add_handler(CommandHandler('scans', require_permission('scan:read')(cmd_scans)))
        app.add_handler(CommandHandler('scan', require_permission('scan:read')(cmd_scan)))
        app.add_handler(CommandHandler('findings', require_permission('scan:read')(cmd_findings)))
        app.add_handler(CommandHandler('assets', require_permission('scan:read')(cmd_assets)))
        app.add_handler(CommandHandler('help', cmd_help))

        # Engineer commands (scan:write)
        app.add_handler(CommandHandler('newscan', require_permission('scan:write')(cmd_newscan)))
        app.add_handler(CommandHandler('cancel', require_permission('scan:write')(cmd_cancel)))
        app.add_handler(CommandHandler('schedule', require_permission('scan:write')(cmd_schedule)))
        app.add_handler(CommandHandler('report', require_permission('scan:write')(cmd_report)))

        # Owner commands
        app.add_handler(CommandHandler('users', require_permission('user:manage')(cmd_users)))
        app.add_handler(CommandHandler('config', require_permission('site:config')(cmd_config)))
        app.add_handler(CommandHandler('health', require_permission('site:config')(cmd_health)))

        # Callback queries (inline buttons)
        app.add_handler(CallbackQueryHandler(handle_callback))

        # Plain text messages (reply keyboard buttons + free-text input)
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

        # Start Redis pub/sub listener in background thread.
        # Must capture the main event loop BEFORE run_polling() takes ownership.
        main_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(main_loop)
        self._start_pubsub_listener(app, cfg, main_loop)

        app.run_polling(
            allowed_updates=Update.ALL_TYPES,
            drop_pending_updates=True,
        )

    def _start_pubsub_listener(self, app, cfg, main_loop):
        """Listen for notification events from worker containers via Redis pub/sub."""
        broker_url = getattr(settings, 'CELERY_BROKER_URL', '')
        if not broker_url:
            log.warning('No CELERY_BROKER_URL configured, skipping pub/sub listener')
            return

        def _listener():
            while True:
                try:
                    r = redis.Redis.from_url(broker_url)
                    pubsub = r.pubsub()
                    pubsub.subscribe('wireghost:bot:notify')
                    log.info('Redis pub/sub listener started on wireghost:bot:notify')

                    for message in pubsub.listen():
                        if message['type'] != 'message':
                            continue
                        try:
                            data = json.loads(message['data'])
                            chat_id = data.get('chat_id')
                            text = data.get('text', '')
                            document_path = data.get('document_path')

                            if not chat_id:
                                chat_id = cfg.telegram_shared_chat_id
                            if not chat_id:
                                continue

                            cid = int(chat_id)
                            if document_path and os.path.isfile(document_path):
                                with open(document_path, 'rb') as f:
                                    future = asyncio.run_coroutine_threadsafe(
                                        app.bot.send_document(
                                            chat_id=cid, document=f,
                                            caption=text[:1024] if text else None,
                                            parse_mode='HTML',
                                        ),
                                        main_loop,
                                    )
                                    future.result(timeout=30)
                            elif document_path:
                                log.warning('Document not found: %s', document_path)
                            elif text:
                                kwargs = dict(chat_id=cid, text=text, parse_mode='HTML')
                                reply_markup_data = data.get('reply_markup')
                                if reply_markup_data:
                                    from telegram import InlineKeyboardButton, InlineKeyboardMarkup
                                    kwargs['reply_markup'] = InlineKeyboardMarkup([
                                        [InlineKeyboardButton(btn['text'], callback_data=btn['callback_data'])
                                         for btn in row]
                                        for row in reply_markup_data
                                    ])
                                future = asyncio.run_coroutine_threadsafe(
                                    app.bot.send_message(**kwargs),
                                    main_loop,
                                )
                                future.result(timeout=30)
                        except Exception:
                            log.exception('Error processing pub/sub message')
                except Exception:
                    log.exception('Redis pub/sub listener crashed, reconnecting in 10s')
                    time.sleep(10)

        thread = threading.Thread(target=_listener, daemon=True, name='bot-pubsub')
        thread.start()
