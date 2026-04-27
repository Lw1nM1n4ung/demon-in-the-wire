import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from django.test import TestCase
from telegram.error import BadRequest

from scanner.bot.callbacks import handle_callback, PERMS


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
    query.message = MagicMock()
    query.message.chat_id = 12345

    update = MagicMock()
    update.callback_query = query
    return update, query


class TestCallbackRouter(TestCase):

    def test_noop_returns_early(self):
        update, query = _make_update(10001, 'noop')
        run_async(handle_callback(update, MagicMock()))
        query.answer.assert_called_once()
        query.edit_message_text.assert_not_called()

    def test_no_query_data_returns(self):
        update, query = _make_update(10001, '')
        query.data = ''
        run_async(handle_callback(update, MagicMock()))
        query.edit_message_text.assert_not_called()

    def test_null_query_returns(self):
        update = MagicMock()
        update.callback_query = None
        run_async(handle_callback(update, MagicMock()))

    @patch('scanner.bot.callbacks.resolve_user')
    def test_unlinked_user_rejected(self, mock_resolve):
        mock_resolve.return_value = None
        update, query = _make_update(99999, 'sl:0')
        run_async(handle_callback(update, MagicMock()))
        query.edit_message_text.assert_called()
        self.assertIn('Not linked', query.edit_message_text.call_args[0][0])

    @patch('scanner.bot.callbacks.resolve_user')
    def test_permission_denied_for_scan_write(self, mock_resolve):
        mock_user = MagicMock()
        mock_user.has_permission.return_value = False
        mock_resolve.return_value = mock_user
        update, query = _make_update(10002, 'sr:abcd1234')
        run_async(handle_callback(update, MagicMock()))
        query.edit_message_text.assert_called()
        self.assertIn('Permission denied', query.edit_message_text.call_args[0][0])

    @patch('scanner.bot.callbacks.resolve_user')
    def test_permission_denied_for_site_config(self, mock_resolve):
        mock_user = MagicMock()
        mock_user.has_permission.return_value = False
        mock_resolve.return_value = mock_user
        update, query = _make_update(10003, 'hl')
        run_async(handle_callback(update, MagicMock()))
        query.edit_message_text.assert_called()
        self.assertIn('Permission denied', query.edit_message_text.call_args[0][0])
        self.assertIn('site:config', query.edit_message_text.call_args[0][0])

    @patch('scanner.bot.callbacks.resolve_user')
    def test_unknown_entity_no_crash(self, mock_resolve):
        mock_user = MagicMock()
        mock_resolve.return_value = mock_user
        update, query = _make_update(10001, 'zzz:unknown')
        run_async(handle_callback(update, MagicMock()))
        query.edit_message_text.assert_not_called()

    @patch('scanner.bot.callbacks.resolve_user')
    def test_menu_no_permission_required(self, mock_resolve):
        mock_user = MagicMock()
        mock_resolve.return_value = mock_user
        update, query = _make_update(10001, 'mn')
        self.assertIsNone(PERMS.get('mn'))


class TestPermsRoutesConsistency(TestCase):

    def test_all_routes_have_perms(self):
        from scanner.bot.callbacks import _build_routes
        routes = _build_routes()
        for entity in routes:
            self.assertIn(entity, PERMS, f'Route {entity!r} missing from PERMS dict')

    def test_all_perms_have_routes_or_special(self):
        from scanner.bot.callbacks import _build_routes
        routes = _build_routes()
        for entity in PERMS:
            if entity == 'noop':
                continue
            self.assertIn(entity, routes, f'PERMS entity {entity!r} missing from ROUTES dict')

    def test_perm_values_are_valid(self):
        valid_perms = {None, 'scan:read', 'scan:write', 'site:config', 'user:manage', 'user:manage'}
        for entity, perm in PERMS.items():
            self.assertIn(perm, valid_perms, f'Invalid perm {perm!r} for entity {entity!r}')


class TestCallbackDataParsing(TestCase):

    @patch('scanner.bot.callbacks.resolve_user')
    def test_parses_entity_and_rest(self, mock_resolve):
        mock_user = MagicMock()
        mock_user.has_permission.return_value = True
        mock_resolve.return_value = mock_user

        from scanner.bot.callbacks import _build_routes
        routes = _build_routes()

        with patch.dict(routes, {'sf': AsyncMock()}, clear=False):
            from scanner.bot.callbacks import ROUTES
            original = dict(ROUTES) if ROUTES else {}
            try:
                import scanner.bot.callbacks as cb_mod
                cb_mod.ROUTES = routes
                cb_mod.ROUTES['sf'] = AsyncMock()

                update, query = _make_update(10001, 'sf:abc12345:0:high')
                run_async(handle_callback(update, MagicMock()))

                cb_mod.ROUTES['sf'].assert_called_once()
                call_args = cb_mod.ROUTES['sf'].call_args
                rest = call_args[0][2]
                self.assertEqual(rest, ['abc12345', '0', 'high'])
            finally:
                cb_mod.ROUTES = original or None


class TestMessageNotModified(TestCase):

    @patch('scanner.bot.callbacks.resolve_user')
    def test_message_not_modified_silently_ignored(self, mock_resolve):
        mock_user = MagicMock()
        mock_user.has_permission.return_value = True
        mock_resolve.return_value = mock_user

        import scanner.bot.callbacks as cb_mod
        original = cb_mod.ROUTES

        async def _raise_not_modified(query, user, rest, context):
            raise BadRequest(
                'Message is not modified: specified new message content and '
                'reply markup are exactly the same as a current content and '
                'reply markup of the message'
            )

        try:
            cb_mod.ROUTES = cb_mod._build_routes()
            cb_mod.ROUTES['mn'] = _raise_not_modified

            update, query = _make_update(10001, 'mn:dash')
            run_async(handle_callback(update, MagicMock()))
            query.edit_message_text.assert_not_called()
        finally:
            cb_mod.ROUTES = original

    @patch('scanner.bot.callbacks.resolve_user')
    def test_other_bad_request_still_shows_error(self, mock_resolve):
        mock_user = MagicMock()
        mock_user.has_permission.return_value = True
        mock_resolve.return_value = mock_user

        import scanner.bot.callbacks as cb_mod
        original = cb_mod.ROUTES

        async def _raise_other_bad_request(query, user, rest, context):
            raise BadRequest('Chat not found')

        try:
            cb_mod.ROUTES = cb_mod._build_routes()
            cb_mod.ROUTES['mn'] = _raise_other_bad_request

            update, query = _make_update(10001, 'mn')
            run_async(handle_callback(update, MagicMock()))
            query.edit_message_text.assert_called()
            self.assertIn('Something went wrong', query.edit_message_text.call_args[0][0])
        finally:
            cb_mod.ROUTES = original
