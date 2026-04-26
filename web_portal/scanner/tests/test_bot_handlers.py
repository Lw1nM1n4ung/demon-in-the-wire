from unittest.mock import AsyncMock, MagicMock, patch
from django.test import TestCase
from scanner.models import User, UserPreference, Scan, Finding, Host, Asset
from scanner.bot.handlers import cmd_status, cmd_scans, cmd_scan, cmd_findings, cmd_assets, cmd_help


def _make_context(user):
    ctx = MagicMock()
    ctx.user_data = {'wg_user': user}
    ctx.args = []
    return ctx


def _make_update(text='/status', args=None):
    update = MagicMock()
    update.effective_user = MagicMock()
    update.effective_user.id = 12345
    update.effective_chat = MagicMock()
    update.effective_chat.id = 67890
    update.message = MagicMock()
    update.message.text = text
    update.message.reply_text = AsyncMock()
    return update


class TestStatusCommand(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='viewer1', password='pass1234', role='viewer',
        )
        prefs = UserPreference.for_user(self.user)
        prefs.telegram_user_id = 12345
        prefs.save()
        Scan.objects.create(
            name='Test Scan', target='10.0.0.0/24', scan_type='full',
            status='completed', created_by=self.user,
            hosts_count=5, findings_count=10, critical_count=1,
            high_count=2, medium_count=3, low_count=4,
        )

    async def test_status_shows_counts(self):
        update = _make_update('/status')
        ctx = _make_context(self.user)
        await cmd_status(update, ctx)
        reply = update.message.reply_text.call_args[0][0]
        assert 'Total hosts' in reply or 'hosts' in reply.lower()
        assert 'findings' in reply.lower()


class TestScansCommand(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='viewer2', password='pass1234', role='viewer',
        )
        for i in range(3):
            Scan.objects.create(
                name=f'Scan {i}', target=f'10.0.{i}.0/24',
                scan_type='full', status='completed', created_by=self.user,
                findings_count=i * 10,
            )

    async def test_scans_lists_recent(self):
        update = _make_update('/scans')
        ctx = _make_context(self.user)
        await cmd_scans(update, ctx)
        reply = update.message.reply_text.call_args[0][0]
        assert '10.0.0.0/24' in reply
        assert '10.0.1.0/24' in reply
        assert '10.0.2.0/24' in reply


class TestHelpCommand(TestCase):
    def setUp(self):
        self.viewer = User.objects.create_user(
            username='helpviewer', password='pass1234', role='viewer',
        )

    async def test_help_shows_commands(self):
        update = _make_update('/help')
        ctx = _make_context(self.viewer)
        await cmd_help(update, ctx)
        reply = update.message.reply_text.call_args[0][0]
        assert '/status' in reply
        assert '/scans' in reply
