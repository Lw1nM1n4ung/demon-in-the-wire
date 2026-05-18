"""Tests for AD Recon Celery task -- 7-phase sequential execution."""
from unittest.mock import patch

from django.test import TestCase

from scanner.models import User
from scanner.models.ad_recon import CredentialProfile, ADReconSession


_sentinel = object()


class TestADReconTask(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username='adrecon', password='test')
        self.profile = CredentialProfile.objects.create(
            owner=self.user,
            name='AD Lab',
            domain='lab.local',
            username='admin',
            password='Secret123',
            nt_hash='aad3b435b51404eeaad3b435b51404ee',
        )

    def _create_session(self, scope='authenticated', profile=_sentinel):
        if profile is _sentinel:
            profile = self.profile
        return ADReconSession.objects.create(
            profile=profile,
            scope=scope,
            dc_ip='10.0.0.1',
            domain='lab.local',
        )

    @patch('scanner.tasks.ad_recon._run_tool')
    def test_phase0_failure_aborts_session(self, mock_run_tool):
        mock_run_tool.return_value = (1, '', 'Connection refused')
        session = self._create_session()

        from scanner.tasks.ad_recon import ad_recon_task
        result = ad_recon_task(session.id)

        session.refresh_from_db()
        self.assertEqual(session.status, 'failed')
        self.assertIn('Phase 0 failed', session.error)
        self.assertEqual(result['status'], 'failed')

    @patch('scanner.tasks.ad_recon._run_tool')
    def test_phase0_success_proceeds_to_phase1(self, mock_run_tool):
        mock_run_tool.return_value = (0, '', '')
        session = self._create_session()

        from scanner.tasks.ad_recon import ad_recon_task
        result = ad_recon_task(session.id)

        session.refresh_from_db()
        self.assertEqual(session.status, 'complete')
        self.assertIn('nxc_connectivity', session.tool_status)
        self.assertIn('ldapdomaindump', session.tool_status)
        self.assertIn('nxc_shares', session.tool_status)
        self.assertEqual(result['status'], 'complete')

    @patch('scanner.tasks.ad_recon._run_tool')
    def test_unauth_scope_skips_credential_phases(self, mock_run_tool):
        mock_run_tool.return_value = (0, '', '')
        session = self._create_session(scope='unauth', profile=None)

        from scanner.tasks.ad_recon import ad_recon_task
        result = ad_recon_task(session.id)

        session.refresh_from_db()
        self.assertEqual(session.status, 'complete')
        self.assertIn('kerbrute', session.tool_status)
        self.assertNotIn('impacket_getnpusers', session.tool_status)
        self.assertNotIn('impacket_getspns', session.tool_status)
        self.assertNotIn('impacket_secretsdump', session.tool_status)
        self.assertNotIn('nxc_adcs', session.tool_status)
        self.assertNotIn('rpcclient', session.tool_status)
        self.assertEqual(result['status'], 'complete')

    @patch('scanner.tasks.ad_recon._run_tool')
    def test_tool_timeout_does_not_abort(self, mock_run_tool):
        def _side_effect(tool_name, cmd_args, timeout=60, env=None):
            if tool_name == 'nxc_connectivity':
                return (0, '', '')
            return (None, None, 'timed out')
        mock_run_tool.side_effect = _side_effect
        session = self._create_session()

        from scanner.tasks.ad_recon import ad_recon_task
        result = ad_recon_task(session.id)

        session.refresh_from_db()
        self.assertEqual(session.status, 'complete')
        self.assertIn('ldapdomaindump', session.tool_status)
        self.assertIn('timed out', session.tool_status['ldapdomaindump']['error'])
        self.assertEqual(result['status'], 'complete')

    @patch('scanner.tasks.ad_recon._run_tool')
    def test_missing_binary_skipped_gracefully(self, mock_run_tool):
        def _side_effect(tool_name, cmd_args, timeout=60, env=None):
            if tool_name == 'nxc_connectivity':
                return (0, '', '')
            if tool_name == 'ldapdomaindump':
                return (None, None, 'ldapdomaindump: binary not found')
            return (0, '', '')
        mock_run_tool.side_effect = _side_effect
        session = self._create_session()

        from scanner.tasks.ad_recon import ad_recon_task
        result = ad_recon_task(session.id)

        session.refresh_from_db()
        self.assertEqual(session.status, 'complete')
        self.assertIn('ldapdomaindump', session.tool_status)
        self.assertIn('binary not found', session.tool_status['ldapdomaindump']['error'])
        self.assertEqual(result['status'], 'complete')
