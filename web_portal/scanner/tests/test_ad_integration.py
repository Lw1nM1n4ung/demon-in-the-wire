"""Integration tests for AD recon — full session lifecycle with mocked tools."""
from unittest.mock import patch

from django.test import TestCase
from rest_framework.test import APIClient

from scanner.models import User, Permission, RolePermission
from scanner.models.ad_recon import (
    CredentialProfile, ADReconSession, ADUser, ADGroup, ADSPN, ADACL,
)


class TestADReconIntegration(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username='adinteg', password='test')
        self.user.role = 'engineer'
        self.user.save(update_fields=['role'])
        perm, _ = Permission.objects.get_or_create(
            code='site:config', defaults={'name': 'Site Config'})
        RolePermission.objects.get_or_create(role=self.user.role, permission=perm)
        self.client = APIClient()
        self.client.force_login(self.user)

    # ── Credential Profile Lifecycle ──

    def test_profile_crud_lifecycle(self):
        """Create, read, update, delete a credential profile."""
        # Create
        r = self.client.post('/api/ad-recon/profiles/', {
            'name': 'Integration Lab', 'domain': 'test.local',
            'username': 'admin', 'password': 'Secret123',
        }, format='json')
        self.assertEqual(r.status_code, 201)
        data = r.json()
        self.assertNotIn('password', data)
        self.assertNotIn('nt_hash', data)
        self.assertEqual(data['name'], 'Integration Lab')
        pid = data['id']

        # Read (list)
        r = self.client.get('/api/ad-recon/profiles/')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['count'], 1)

        # Read (detail)
        r = self.client.get(f'/api/ad-recon/profiles/{pid}/')
        self.assertEqual(r.status_code, 200)
        self.assertNotIn('password', r.json())

        # Update
        r = self.client.put(f'/api/ad-recon/profiles/{pid}/', {
            'name': 'Updated Lab', 'domain': 'test.local',
            'username': 'admin', 'password': 'NewSecret456',
        }, format='json')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['name'], 'Updated Lab')

        # Delete
        r = self.client.delete(f'/api/ad-recon/profiles/{pid}/')
        self.assertEqual(r.status_code, 204)
        r = self.client.get('/api/ad-recon/profiles/')
        self.assertEqual(r.json()['count'], 0)

    # ── Session Lifecycle ──

    @patch('scanner.tasks.ad_recon.ad_recon_task.delay')
    def test_authenticated_session_lifecycle(self, mock_delay):
        """Full lifecycle: create profile → start session → task dispatch."""
        profile = CredentialProfile.objects.create(
            owner=self.user, name='Auth Lab', domain='test.local',
            username='admin', password='Secret123',
        )

        r = self.client.post('/api/ad-recon/sessions/', {
            'profile': str(profile.id), 'scope': 'authenticated',
            'dc_ip': '10.0.0.1', 'domain': 'test.local',
        }, format='json')
        self.assertEqual(r.status_code, 201)
        data = r.json()
        self.assertEqual(data['status'], 'pending')
        self.assertEqual(data['profile_name'], 'Auth Lab')
        session_id = data['id']
        mock_delay.assert_called_once_with(str(session_id))

        r = self.client.get(f'/api/ad-recon/sessions/{session_id}/')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['status'], 'pending')

    @patch('scanner.tasks.ad_recon.ad_recon_task.delay')
    def test_unauth_session_no_profile(self, mock_delay):
        r = self.client.post('/api/ad-recon/sessions/', {
            'scope': 'unauth', 'dc_ip': '10.0.0.1', 'domain': 'test.local',
        }, format='json')
        self.assertEqual(r.status_code, 201)
        data = r.json()
        self.assertEqual(data['status'], 'pending')
        self.assertIsNone(data['profile'])
        self.assertIsNone(data['profile_name'])
        mock_delay.assert_called_once()

    def test_auth_session_without_profile_rejected(self):
        r = self.client.post('/api/ad-recon/sessions/', {
            'scope': 'authenticated', 'dc_ip': '10.0.0.1', 'domain': 'test.local',
        }, format='json')
        self.assertEqual(r.status_code, 400)
        self.assertIn('profile', r.json()['error'].lower())

    def test_unauth_scope_with_profile_rejected(self):
        profile = CredentialProfile.objects.create(
            owner=self.user, name='Extra', domain='test.local',
            username='admin', password='Secret123',
        )
        r = self.client.post('/api/ad-recon/sessions/', {
            'profile': str(profile.id), 'scope': 'unauth',
            'dc_ip': '10.0.0.1', 'domain': 'test.local',
        }, format='json')
        self.assertEqual(r.status_code, 400)
        self.assertIn('profile', r.json()['error'].lower())

    # ── Session Detail / Findings ──

    def test_session_findings_endpoint(self):
        """Session findings endpoint returns SPNs, ACLs, certs, trusts, shares."""
        profile = CredentialProfile.objects.create(
            owner=self.user, name='Findings Lab', domain='test.local',
            username='admin', password='Secret123',
        )
        session = ADReconSession.objects.create(
            profile=profile, scope='authenticated', dc_ip='10.0.0.1',
            domain='test.local', status='complete',
            tool_status={'nxc_connectivity': {'rc': 0, 'ran_at': '2026-01-01T00:00:00Z'}},
        )
        ADSPN.objects.create(session=session, service_name='MSSQLSvc/db.test.local',
                             sam_account_name='sql_svc', host='db.test.local', port=1433)
        ADACL.objects.create(session=session, identity='Domain Users',
                             active_directory_rights='GenericAll',
                             object_dn='DC=test,DC=local')

        r = self.client.get(f'/api/ad-recon/sessions/{session.id}/findings/')
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(len(data['spns']), 1)
        self.assertEqual(data['spns'][0]['service_name'], 'MSSQLSvc/db.test.local')
        self.assertEqual(len(data['acls']), 1)
        self.assertEqual(len(data['cert_services']), 0)
        self.assertEqual(len(data['trusts']), 0)
        self.assertEqual(len(data['shares']), 0)

    def test_session_subresource_endpoints(self):
        """Users, groups, computers, domains sub-resources are reachable."""
        profile = CredentialProfile.objects.create(
            owner=self.user, name='SubRes Lab', domain='test.local',
            username='admin', password='Secret123',
        )
        session = ADReconSession.objects.create(
            profile=profile, scope='authenticated', dc_ip='10.0.0.1',
            domain='test.local', status='complete',
        )
        ADUser.objects.create(session=session, sam_account_name='jsmith',
                              upn='jsmith@test.local', enabled=True)
        ADGroup.objects.create(session=session, name='Domain Admins',
                               sam_account_name='Domain Admins', member_count=5)

        for sub in ('users', 'groups', 'computers', 'domains'):
            r = self.client.get(f'/api/ad-recon/sessions/{session.id}/{sub}/')
            self.assertEqual(r.status_code, 200, f'{sub} endpoint failed')
            self.assertIn('results', r.json())

        r = self.client.get(f'/api/ad-recon/sessions/{session.id}/users/')
        self.assertEqual(r.json()['results'][0]['sam_account_name'], 'jsmith')

        r = self.client.get(f'/api/ad-recon/sessions/{session.id}/groups/')
        self.assertEqual(r.json()['results'][0]['name'], 'Domain Admins')

    # ── Session list ──

    def test_session_list_paginated(self):
        profile = CredentialProfile.objects.create(
            owner=self.user, name='List Lab', domain='test.local',
            username='admin', password='Secret123',
        )
        for i in range(3):
            ADReconSession.objects.create(
                profile=profile, scope='authenticated', dc_ip='10.0.0.1',
                domain='test.local', status='complete',
            )
        r = self.client.get('/api/ad-recon/sessions/')
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data['count'], 3)
        self.assertEqual(len(data['results']), 3)

    # ── Profile isolation ──

    def test_profiles_are_user_scoped(self):
        """User A cannot see User B's profiles."""
        CredentialProfile.objects.create(
            owner=self.user, name='My Profile', domain='test.local',
            username='admin', password='Secret123',
        )
        other = User.objects.create_user(username='other', password='test')
        CredentialProfile.objects.create(
            owner=other, name='Other Profile', domain='other.local',
            username='admin', password='Secret123',
        )

        r = self.client.get('/api/ad-recon/profiles/')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['count'], 1)
        self.assertEqual(r.json()['results'][0]['name'], 'My Profile')

    # ── Permission check ──

    def test_viewer_denied_access(self):
        viewer = User.objects.create_user(username='viewer', password='test')
        client2 = APIClient()
        client2.force_login(viewer)
        r = client2.get('/api/ad-recon/profiles/')
        self.assertEqual(r.status_code, 403)

        r = client2.get('/api/ad-recon/sessions/')
        self.assertEqual(r.status_code, 403)

    # ── Session creation idempotency ──

    @patch('scanner.tasks.ad_recon.ad_recon_task.delay')
    def test_multiple_sessions_independent(self, mock_delay):
        """Creating two sessions should produce two independent records."""
        profile = CredentialProfile.objects.create(
            owner=self.user, name='Multi Lab', domain='test.local',
            username='admin', password='Secret123',
        )
        r1 = self.client.post('/api/ad-recon/sessions/', {
            'profile': str(profile.id), 'scope': 'authenticated',
            'dc_ip': '10.0.0.1', 'domain': 'test.local',
        }, format='json')
        r2 = self.client.post('/api/ad-recon/sessions/', {
            'profile': str(profile.id), 'scope': 'authenticated',
            'dc_ip': '10.0.0.2', 'domain': 'test.local',
        }, format='json')
        self.assertEqual(r1.status_code, 201)
        self.assertEqual(r2.status_code, 201)
        self.assertNotEqual(r1.json()['id'], r2.json()['id'])
        self.assertEqual(mock_delay.call_count, 2)

        r = self.client.get('/api/ad-recon/sessions/')
        self.assertEqual(r.json()['count'], 2)

    # ── Invalid input ──

    def test_create_profile_empty_password_rejected(self):
        r = self.client.post('/api/ad-recon/profiles/', {
            'name': 'Bad', 'domain': 'test.local',
            'username': 'admin', 'password': '',
        }, format='json')
        self.assertEqual(r.status_code, 400)

    def test_create_profile_missing_domain_rejected(self):
        r = self.client.post('/api/ad-recon/profiles/', {
            'name': 'Bad', 'username': 'admin', 'password': 'pass',
        }, format='json')
        self.assertEqual(r.status_code, 400)

    def test_create_session_missing_dc_ip_rejected(self):
        profile = CredentialProfile.objects.create(
            owner=self.user, name='DC Lab', domain='test.local',
            username='admin', password='Secret123',
        )
        r = self.client.post('/api/ad-recon/sessions/', {
            'profile': str(profile.id), 'scope': 'authenticated',
            'domain': 'test.local',
        }, format='json')
        self.assertEqual(r.status_code, 400)
