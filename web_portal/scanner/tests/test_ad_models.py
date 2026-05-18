"""Tests for AD Recon models."""
from django.test import TestCase
from django.db.utils import IntegrityError
from scanner.models import User
from scanner.models.ad_recon import CredentialProfile, ADReconSession


class TestCredentialProfile(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username='adtest', password='test')

    def test_encryption_round_trip(self):
        profile = CredentialProfile.objects.create(
            owner=self.user, name='Lab', domain='lab.local',
            username='admin', password='Secret123',
        )
        self.assertTrue(profile.password.startswith('gAAAAA'))
        self.assertEqual(profile.decrypt_password(), 'Secret123')

    def test_repr_never_leaks_plaintext(self):
        profile = CredentialProfile.objects.create(
            owner=self.user, name='Lab', domain='lab.local',
            username='admin', password='Secret123',
        )
        r = repr(profile)
        self.assertNotIn('Secret123', r)
        self.assertNotIn('gAAAAA', r)

    def test_str_never_leaks_plaintext(self):
        profile = CredentialProfile.objects.create(
            owner=self.user, name='Lab', domain='lab.local',
            username='admin', password='Secret123',
        )
        s = str(profile)
        self.assertNotIn('Secret123', s)

    def test_unique_name_per_user(self):
        CredentialProfile.objects.create(
            owner=self.user, name='Lab', domain='lab.local',
            username='admin', password='Secret123',
        )
        with self.assertRaises(IntegrityError):
            CredentialProfile.objects.create(
                owner=self.user, name='Lab', domain='other.local',
                username='user', password='Pass456',
            )

    def test_both_password_and_nt_hash_empty_raises(self):
        from django.core.exceptions import ValidationError
        with self.assertRaises(ValidationError):
            CredentialProfile.objects.create(
                owner=self.user, name='Empty', domain='lab.local',
                username='admin', password='', nt_hash='',
            )

    def test_nt_hash_encryption(self):
        profile = CredentialProfile.objects.create(
            owner=self.user, name='Hash Lab', domain='lab.local',
            username='admin', password='Secret123',
            nt_hash='aad3b435b51404eeaad3b435b51404ee',
        )
        self.assertTrue(profile.nt_hash.startswith('gAAAAA'))
        self.assertEqual(
            profile.decrypt_nt_hash(),
            'aad3b435b51404eeaad3b435b51404ee',
        )


class TestADReconSession(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username='adtest2', password='test')

    def test_session_scope_choices(self):
        profile = CredentialProfile.objects.create(
            owner=self.user, name='Lab', domain='lab.local',
            username='admin', password='Secret123',
        )
        session = ADReconSession.objects.create(
            profile=profile, scope='authenticated',
            dc_ip='10.0.0.1', domain='lab.local',
        )
        self.assertEqual(session.scope, 'authenticated')
        self.assertEqual(session.status, 'pending')

    def test_session_cascade_on_profile_delete(self):
        profile = CredentialProfile.objects.create(
            owner=self.user, name='Lab', domain='lab.local',
            username='admin', password='Secret123',
        )
        session = ADReconSession.objects.create(
            profile=profile, scope='authenticated',
            dc_ip='10.0.0.1', domain='lab.local',
        )
        profile.delete()
        session.refresh_from_db()
        self.assertIsNone(session.profile)
