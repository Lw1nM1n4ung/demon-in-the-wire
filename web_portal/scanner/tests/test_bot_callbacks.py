import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from django.test import TestCase

from scanner.bot.callbacks import handle_callback


def run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _make_update(tg_user_id, callback_data):
    query = AsyncMock()
    query.data = callback_data
    query.from_user = MagicMock()
    query.from_user.id = tg_user_id
    query.answer = AsyncMock()
    query.edit_message_text = AsyncMock()

    update = MagicMock()
    update.callback_query = query
    return update, query


class TestCallbackRBAC(TestCase):

    @patch('scanner.bot.callbacks.resolve_user')
    def test_report_denied_without_scan_write(self, mock_resolve):
        mock_user = MagicMock()
        mock_user.has_permission.return_value = False
        mock_resolve.return_value = mock_user

        update, query = _make_update(10002, 'scan:abcd1234:report')
        run_async(handle_callback(update, MagicMock()))

        query.edit_message_text.assert_called()
        assert 'Permission denied' in query.edit_message_text.call_args[0][0]

    @patch('scanner.bot.callbacks.Scan')
    @patch('scanner.bot.callbacks.resolve_user')
    def test_report_allowed_with_scan_write(self, mock_resolve, mock_scan_model):
        mock_user = MagicMock()
        mock_user.has_permission.return_value = True
        mock_resolve.return_value = mock_user
        mock_scan_model.objects.filter.return_value.first.return_value = None

        update, query = _make_update(10001, 'scan:abcd1234:report')
        run_async(handle_callback(update, MagicMock()))

        call_text = query.edit_message_text.call_args[0][0]
        assert 'Permission denied' not in call_text

    @patch('scanner.bot.callbacks.resolve_user')
    def test_unlinked_user_rejected(self, mock_resolve):
        mock_resolve.return_value = None

        update, query = _make_update(99999, 'scan:abcd1234:findings')
        run_async(handle_callback(update, MagicMock()))

        query.edit_message_text.assert_called()
        assert 'Not linked' in query.edit_message_text.call_args[0][0]

    @patch('scanner.bot.callbacks.resolve_user')
    def test_malformed_callback_data_ignored(self, mock_resolve):
        mock_user = MagicMock()
        mock_resolve.return_value = mock_user

        update, query = _make_update(10001, 'bad')
        run_async(handle_callback(update, MagicMock()))

        query.edit_message_text.assert_not_called()
