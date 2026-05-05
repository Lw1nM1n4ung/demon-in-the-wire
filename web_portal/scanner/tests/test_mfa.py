"""Tests for Wire_Ghost email-based MFA."""
import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core import mail
from django.core.cache import cache
from django.test import Client, TestCase, override_settings

from scanner.models import UserMfaConfig, MfaBackupCode, UserPreference

User = get_user_model()

STRONG_PW = 'X#kL9$mNp!2qR'


def _make_user(username='mfauser', role='owner'):
    u = User.objects.create_user(username=username, password=STRONG_PW, email=f'{username}@test.local')
    u.role = role
    u.save()
    prefs = UserPreference.for_user(u)
    prefs.telegram_chat_id = '123456789'
    prefs.save()
    return u


def _enable_mfa(user):
    cfg, _ = UserMfaConfig.objects.get_or_create(user=user)
    cfg.enabled = True
    cfg.save()
    return MfaBackupCode.generate_for_user(user)


@override_settings(
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    MFA_OTP_TTL=300, MFA_OTP_LENGTH=6, MFA_MAX_ATTEMPTS=5,
    MFA_MAX_RESENDS=3, MFA_HOURLY_EMAIL_CAP=10,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache', 'LOCATION': 'test-mfa'}},
)
class MfaModelTest(TestCase):
    def test_mfa_config_creation(self):
        user = _make_user()
        cfg = UserMfaConfig.objects.create(user=user, enabled=True)
        self.assertTrue(cfg.enabled)
        self.assertEqual(str(cfg), f'MFA(on) {user.username}')

    def test_backup_code_generate(self):
        user = _make_user()
        codes = MfaBackupCode.generate_for_user(user)
        self.assertEqual(len(codes), 8)
        self.assertEqual(MfaBackupCode.objects.filter(user=user).count(), 8)

    def test_backup_code_verify_and_consume(self):
        user = _make_user()
        codes = MfaBackupCode.generate_for_user(user)
        self.assertTrue(MfaBackupCode.verify_and_consume(user, codes[0]))
        self.assertFalse(MfaBackupCode.verify_and_consume(user, codes[0]))

    def test_backup_code_regenerate_deletes_old(self):
        user = _make_user()
        MfaBackupCode.generate_for_user(user)
        MfaBackupCode.generate_for_user(user)
        self.assertEqual(MfaBackupCode.objects.filter(user=user).count(), 8)


@override_settings(
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    MFA_OTP_TTL=300, MFA_OTP_LENGTH=6, MFA_MAX_ATTEMPTS=5,
    MFA_MAX_RESENDS=3, MFA_HOURLY_EMAIL_CAP=10,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache', 'LOCATION': 'test-mfa-login'}},
)
class MfaLoginFlowTest(TestCase):
    def setUp(self):
        patch('scanner.tasks.send_mfa_otp.delay').start()
        self.user = _make_user()
        _enable_mfa(self.user)
        self.c = Client()
        cache.clear()

    def tearDown(self):
        patch.stopall()

    def test_login_returns_mfa_required(self):
        res = self.c.post('/api/auth/login/', json.dumps({'username': 'mfauser', 'password': STRONG_PW}), content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data['mfa_required'])
        self.assertIn('mfa_token', data)
        self.assertEqual(data['delivery'], 'telegram')

    def test_login_no_session_before_mfa(self):
        res = self.c.post('/api/auth/login/', json.dumps({'username': 'mfauser', 'password': STRONG_PW}), content_type='application/json')
        self.assertEqual(res.status_code, 200)
        check = self.c.get('/api/auth/check/')
        self.assertEqual(check.status_code, 401)

    def test_login_without_mfa_skips_otp(self):
        user2 = _make_user('nomfa', 'engineer')
        res = self.c.post('/api/auth/login/', json.dumps({'username': 'nomfa', 'password': STRONG_PW}), content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertNotIn('mfa_required', data)
        self.assertIn('username', data)


@override_settings(
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    MFA_OTP_TTL=300, MFA_OTP_LENGTH=6, MFA_MAX_ATTEMPTS=5,
    MFA_MAX_RESENDS=3, MFA_HOURLY_EMAIL_CAP=10,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache', 'LOCATION': 'test-mfa-verify'}},
)
class MfaVerifyTest(TestCase):
    def setUp(self):
        patch('scanner.tasks.send_mfa_otp.delay').start()
        self.user = _make_user()
        _enable_mfa(self.user)
        self.c = Client()
        cache.clear()

    def tearDown(self):
        patch.stopall()

    def _login_get_token(self):
        res = self.c.post('/api/auth/login/', json.dumps({'username': 'mfauser', 'password': STRONG_PW}), content_type='application/json')
        return res.json()['mfa_token']

    def _get_otp(self, token):
        pending = cache.get(f'mfa_pending:{token}')
        return pending['otp']

    def test_valid_otp_creates_session(self):
        token = self._login_get_token()
        otp = self._get_otp(token)
        res = self.c.post('/api/auth/mfa/verify/', json.dumps({'mfa_token': token, 'code': otp}), content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertIn('username', res.json())
        check = self.c.get('/api/auth/check/')
        self.assertEqual(check.status_code, 204)

    def test_invalid_otp_returns_401(self):
        token = self._login_get_token()
        res = self.c.post('/api/auth/mfa/verify/', json.dumps({'mfa_token': token, 'code': '000000'}), content_type='application/json')
        self.assertEqual(res.status_code, 401)
        self.assertIn('attempts remaining', res.json()['error'])

    def test_expired_token_returns_401(self):
        res = self.c.post('/api/auth/mfa/verify/', json.dumps({'mfa_token': 'bogus', 'code': '123456'}), content_type='application/json')
        self.assertEqual(res.status_code, 401)
        self.assertIn('expired', res.json()['error'])

    def test_max_attempts_locks_out(self):
        token = self._login_get_token()
        for _ in range(5):
            self.c.post('/api/auth/mfa/verify/', json.dumps({'mfa_token': token, 'code': '000000'}), content_type='application/json')
        res = self.c.post('/api/auth/mfa/verify/', json.dumps({'mfa_token': token, 'code': '000000'}), content_type='application/json')
        self.assertEqual(res.status_code, 429)


@override_settings(
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    MFA_OTP_TTL=300, MFA_OTP_LENGTH=6, MFA_MAX_ATTEMPTS=5,
    MFA_MAX_RESENDS=3, MFA_HOURLY_EMAIL_CAP=10,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache', 'LOCATION': 'test-mfa-backup'}},
)
class MfaBackupCodeLoginTest(TestCase):
    def setUp(self):
        patch('scanner.tasks.send_mfa_otp.delay').start()
        self.user = _make_user()
        self.codes = _enable_mfa(self.user)
        self.c = Client()
        cache.clear()

    def tearDown(self):
        patch.stopall()

    def _login_get_token(self):
        res = self.c.post('/api/auth/login/', json.dumps({'username': 'mfauser', 'password': STRONG_PW}), content_type='application/json')
        return res.json()['mfa_token']

    def test_backup_code_works(self):
        token = self._login_get_token()
        res = self.c.post('/api/auth/mfa/verify/', json.dumps({'mfa_token': token, 'code': self.codes[0]}), content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertIn('username', res.json())

    def test_used_backup_code_rejected(self):
        token = self._login_get_token()
        self.c.post('/api/auth/mfa/verify/', json.dumps({'mfa_token': token, 'code': self.codes[0]}), content_type='application/json')
        self.c.logout()
        cache.clear()
        token2 = self._login_get_token()
        res = self.c.post('/api/auth/mfa/verify/', json.dumps({'mfa_token': token2, 'code': self.codes[0]}), content_type='application/json')
        self.assertEqual(res.status_code, 401)


@override_settings(
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    MFA_OTP_TTL=300, MFA_OTP_LENGTH=6, MFA_MAX_ATTEMPTS=5,
    MFA_MAX_RESENDS=3, MFA_HOURLY_EMAIL_CAP=10,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache', 'LOCATION': 'test-mfa-resend'}},
)
class MfaResendTest(TestCase):
    def setUp(self):
        patch('scanner.tasks.send_mfa_otp.delay').start()
        self.user = _make_user()
        _enable_mfa(self.user)
        self.c = Client()
        cache.clear()

    def tearDown(self):
        patch.stopall()

    def _login_get_token(self):
        res = self.c.post('/api/auth/login/', json.dumps({'username': 'mfauser', 'password': STRONG_PW}), content_type='application/json')
        return res.json()['mfa_token']

    def test_resend_generates_new_otp(self):
        token = self._login_get_token()
        old_otp = cache.get(f'mfa_pending:{token}')['otp']
        res = self.c.post('/api/auth/mfa/resend/', json.dumps({'mfa_token': token}), content_type='application/json')
        self.assertEqual(res.status_code, 200)
        new_otp = cache.get(f'mfa_pending:{token}')['otp']
        self.assertNotEqual(old_otp, new_otp)

    def test_max_resends_enforced(self):
        token = self._login_get_token()
        for _ in range(3):
            self.c.post('/api/auth/mfa/resend/', json.dumps({'mfa_token': token}), content_type='application/json')
        res = self.c.post('/api/auth/mfa/resend/', json.dumps({'mfa_token': token}), content_type='application/json')
        self.assertEqual(res.status_code, 429)


@override_settings(
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    MFA_OTP_TTL=300, MFA_OTP_LENGTH=6, MFA_MAX_ATTEMPTS=5,
    MFA_MAX_RESENDS=3, MFA_HOURLY_EMAIL_CAP=10,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache', 'LOCATION': 'test-mfa-setup'}},
)
class MfaSetupTest(TestCase):
    def setUp(self):
        patch('scanner.tasks.send_mfa_otp.delay').start()
        self.user = _make_user()
        self.c = Client()
        cache.clear()
        self.c.login(username='mfauser', password=STRONG_PW)

    def tearDown(self):
        patch.stopall()

    def test_setup_requires_reauth(self):
        res = self.c.post('/api/auth/mfa/setup/', content_type='application/json')
        self.assertEqual(res.status_code, 403)

    def test_full_setup_flow(self):
        cache.set(f'reauth:{self.user.id}', True, 300)
        res = self.c.post('/api/auth/mfa/setup/', content_type='application/json')
        self.assertEqual(res.status_code, 200)
        setup_token = res.json()['setup_token']

        otp = cache.get(f'mfa_setup:{setup_token}')['otp']
        res = self.c.post('/api/auth/mfa/confirm/', json.dumps({'setup_token': setup_token, 'code': otp}), content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data['enabled'])
        self.assertEqual(len(data['backup_codes']), 8)
        self.assertTrue(UserMfaConfig.objects.get(user=self.user).enabled)

    def test_confirm_wrong_code_fails(self):
        cache.set(f'reauth:{self.user.id}', True, 300)
        res = self.c.post('/api/auth/mfa/setup/', content_type='application/json')
        setup_token = res.json()['setup_token']
        res = self.c.post('/api/auth/mfa/confirm/', json.dumps({'setup_token': setup_token, 'code': '000000'}), content_type='application/json')
        self.assertEqual(res.status_code, 401)


@override_settings(
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    MFA_OTP_TTL=300, MFA_OTP_LENGTH=6, MFA_MAX_ATTEMPTS=5,
    MFA_MAX_RESENDS=3, MFA_HOURLY_EMAIL_CAP=10,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache', 'LOCATION': 'test-mfa-disable'}},
)
class MfaDisableTest(TestCase):
    def setUp(self):
        self.user = _make_user()
        _enable_mfa(self.user)
        self.c = Client()
        cache.clear()
        self.c.login(username='mfauser', password=STRONG_PW)

    def test_disable_requires_reauth(self):
        res = self.c.post('/api/auth/mfa/disable/', content_type='application/json')
        self.assertEqual(res.status_code, 403)

    def test_disable_clears_mfa(self):
        cache.set(f'reauth:{self.user.id}', True, 300)
        res = self.c.post('/api/auth/mfa/disable/', content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertFalse(res.json()['enabled'])
        self.assertFalse(UserMfaConfig.objects.get(user=self.user).enabled)
        self.assertEqual(MfaBackupCode.objects.filter(user=self.user).count(), 0)


@override_settings(
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    MFA_OTP_TTL=300, MFA_OTP_LENGTH=6, MFA_MAX_ATTEMPTS=5,
    MFA_MAX_RESENDS=3, MFA_HOURLY_EMAIL_CAP=10,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache', 'LOCATION': 'test-mfa-cmd'}},
)
class MfaManagementCommandTest(TestCase):
    def test_mfa_disable_command(self):
        from django.core.management import call_command
        from io import StringIO
        user = _make_user()
        _enable_mfa(user)
        self.assertTrue(UserMfaConfig.objects.get(user=user).enabled)

        out = StringIO()
        call_command('mfa_disable', 'mfauser', stdout=out)
        self.assertIn('MFA disabled', out.getvalue())
        user.refresh_from_db()
        self.assertFalse(UserMfaConfig.objects.get(user=user).enabled)
        self.assertEqual(MfaBackupCode.objects.filter(user=user).count(), 0)
