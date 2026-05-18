"""Tests for AD Recon views."""
from unittest.mock import patch

from django.test import TestCase
from rest_framework.test import APIClient

from scanner.models import User, Permission, RolePermission
from scanner.models.ad_recon import CredentialProfile, ADReconSession


class TestADReconViews(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username='adviewtest', password='test')
        self.user.role = 'engineer'
        self.user.save(update_fields=['role'])
        perm, _ = Permission.objects.get_or_create(
            code='site:config', defaults={'name': 'Site Config'})
        RolePermission.objects.get_or_create(role=self.user.role, permission=perm)
        self.client = APIClient()
        self.client.force_login(self.user)

    def test_list_profiles_empty(self):
        r = self.client.get('/api/ad-recon/profiles/')
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data['count'], 0)
        self.assertEqual(data['results'], [])

    def test_create_profile_password_redacted(self):
        r = self.client.post('/api/ad-recon/profiles/', {
            'name': 'Lab', 'domain': 'lab.local',
            'username': 'admin', 'password': 'Secret123',
        }, format='json')
        self.assertEqual(r.status_code, 201)
        data = r.json()
        self.assertNotIn('password', data)
        self.assertNotIn('nt_hash', data)
        self.assertEqual(data['name'], 'Lab')

    @patch('scanner.tasks.ad_recon.ad_recon_task.delay')
    def test_create_session_authenticated(self, mock_delay):
        profile = CredentialProfile.objects.create(
            owner=self.user, name='Lab', domain='lab.local',
            username='admin', password='Secret123',
        )
        r = self.client.post('/api/ad-recon/sessions/', {
            'profile': str(profile.id), 'scope': 'authenticated',
            'dc_ip': '10.0.0.1', 'domain': 'lab.local',
        }, format='json')
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.json()['status'], 'pending')
        mock_delay.assert_called_once()

    @patch('scanner.tasks.ad_recon.ad_recon_task.delay')
    def test_create_session_unauth_no_profile(self, mock_delay):
        r = self.client.post('/api/ad-recon/sessions/', {
            'scope': 'unauth', 'dc_ip': '10.0.0.1', 'domain': 'lab.local',
        }, format='json')
        self.assertEqual(r.status_code, 201)
        mock_delay.assert_called_once()

    def test_create_session_auth_without_profile_rejected(self):
        r = self.client.post('/api/ad-recon/sessions/', {
            'scope': 'authenticated', 'dc_ip': '10.0.0.1', 'domain': 'lab.local',
        }, format='json')
        self.assertEqual(r.status_code, 400)
        self.assertIn('profile', r.json()['error'].lower())

    def test_403_for_non_site_config_user(self):
        viewer = User.objects.create_user(username='viewer', password='test')
        client2 = APIClient()
        client2.force_login(viewer)
        r = client2.get('/api/ad-recon/profiles/')
        self.assertEqual(r.status_code, 403)
