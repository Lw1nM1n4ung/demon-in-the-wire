"""Integration tests — Celery task registration, scheduled scans, deadline enforcement.

All tests mock out the actual pipeline and Redis/Celery broker so they run
against the in-memory test DB only.
"""

from datetime import time as dtime, timedelta
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from scanner.models import (
    Permission,
    RolePermission,
    Scan,
    ScanPolicy,
    ScheduledScan,
    SiteConfig,
)

User = get_user_model()


class TaskRegistrationTests(TestCase):
    def test_run_scan_registered(self):
        from scanner.tasks import run_scan
        self.assertTrue(hasattr(run_scan, 'delay'))
        self.assertEqual(run_scan.name, 'scanner.tasks.run_scan')

    def test_generate_report_registered(self):
        from scanner.tasks import generate_report
        self.assertTrue(hasattr(generate_report, 'delay'))
        self.assertEqual(generate_report.name, 'scanner.tasks.generate_report')

    def test_check_scheduled_scans_registered(self):
        from scanner.tasks import check_scheduled_scans
        self.assertTrue(hasattr(check_scheduled_scans, 'delay'))

    def test_enforce_scan_deadlines_registered(self):
        from scanner.tasks import enforce_scan_deadlines
        self.assertTrue(hasattr(enforce_scan_deadlines, 'delay'))

    def test_check_for_updates_registered(self):
        from scanner.tasks import check_for_updates
        self.assertTrue(hasattr(check_for_updates, 'delay'))


class ScheduledScanTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_superuser(
            username='owner', password='pw-owner-123!', email='o@test.com',
        )

    @patch('scanner.tasks.run_scan.delay')
    def test_due_schedule_launches_scan(self, mock_delay):
        mock_delay.return_value = MagicMock(id='task-sched-1')
        ScheduledScan.objects.create(
            name='Nightly',
            target='203.0.113.0/24',
            frequency='daily',
            time=dtime(2, 0),
            enabled=True,
            next_run=timezone.now() - timedelta(minutes=5),
            created_by=self.owner,
        )
        from scanner.tasks import check_scheduled_scans
        result = check_scheduled_scans()
        self.assertEqual(result['launched'], 1)
        mock_delay.assert_called_once()
        scan = Scan.objects.get(name__contains='Nightly')
        self.assertEqual(scan.status, 'running')

    @patch('scanner.tasks.run_scan.delay')
    def test_future_schedule_not_launched(self, mock_delay):
        ScheduledScan.objects.create(
            name='Future',
            target='203.0.113.0/24',
            frequency='daily',
            time=dtime(2, 0),
            enabled=True,
            next_run=timezone.now() + timedelta(hours=6),
            created_by=self.owner,
        )
        from scanner.tasks import check_scheduled_scans
        result = check_scheduled_scans()
        self.assertEqual(result['launched'], 0)
        mock_delay.assert_not_called()

    @patch('scanner.tasks.run_scan.delay')
    def test_disabled_schedule_not_launched(self, mock_delay):
        ScheduledScan.objects.create(
            name='Disabled',
            target='203.0.113.0/24',
            frequency='daily',
            time=dtime(2, 0),
            enabled=False,
            next_run=timezone.now() - timedelta(minutes=5),
            created_by=self.owner,
        )
        from scanner.tasks import check_scheduled_scans
        result = check_scheduled_scans()
        self.assertEqual(result['launched'], 0)

    @patch('scanner.tasks.run_scan.delay')
    def test_schedule_next_run_advanced(self, mock_delay):
        mock_delay.return_value = MagicMock(id='t')
        sched = ScheduledScan.objects.create(
            name='Advance',
            target='203.0.113.0/24',
            frequency='daily',
            time=dtime(2, 0),
            enabled=True,
            next_run=timezone.now() - timedelta(minutes=1),
            created_by=self.owner,
        )
        from scanner.tasks import check_scheduled_scans
        check_scheduled_scans()
        sched.refresh_from_db()
        self.assertGreater(sched.next_run, timezone.now())

    @patch('scanner.tasks.run_scan.delay')
    def test_policy_settings_applied(self, mock_delay):
        mock_delay.return_value = MagicMock(id='t')
        policy = ScanPolicy.objects.create(
            name='Custom',
            scan_type='quick',
            parallelism=3,
            timeout=1800,
            tools={'nikto': False, 'netexec': False},
            created_by=self.owner,
        )
        ScheduledScan.objects.create(
            name='WithPolicy',
            target='203.0.113.0/24',
            frequency='daily',
            time=dtime(2, 0),
            enabled=True,
            next_run=timezone.now() - timedelta(minutes=1),
            policy=policy,
            created_by=self.owner,
        )
        from scanner.tasks import check_scheduled_scans
        check_scheduled_scans()
        scan = Scan.objects.get(name__contains='WithPolicy')
        self.assertEqual(scan.scan_type, 'quick')
        self.assertEqual(scan.parallelism, 3)
        self.assertEqual(scan.timeout, 1800)
        self.assertTrue(scan.skip_nikto)
        self.assertTrue(scan.skip_netexec)


class DeadlineEnforcementTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_superuser(
            username='owner', password='pw-owner-123!', email='o@test.com',
        )

    @patch('wireghost_web.celery.app')
    def test_overdue_scan_cancelled(self, mock_celery):
        scan = Scan.objects.create(
            name='overdue', target='203.0.113.1',
            status='running', celery_task_id='task-dead',
            deadline=timezone.now() - timedelta(minutes=10),
            started_at=timezone.now() - timedelta(hours=2),
            created_by=self.owner,
        )
        from scanner.tasks import enforce_scan_deadlines
        result = enforce_scan_deadlines()
        self.assertEqual(result['cancelled'], 1)
        scan.refresh_from_db()
        self.assertEqual(scan.status, 'cancelled')
        self.assertIn('exceeded stop time', scan.error_message)

    def test_future_deadline_not_cancelled(self):
        scan = Scan.objects.create(
            name='still-running', target='203.0.113.1',
            status='running', celery_task_id='task-ok',
            deadline=timezone.now() + timedelta(hours=1),
            created_by=self.owner,
        )
        from scanner.tasks import enforce_scan_deadlines
        result = enforce_scan_deadlines()
        self.assertEqual(result['cancelled'], 0)
        scan.refresh_from_db()
        self.assertEqual(scan.status, 'running')

    def test_completed_scan_not_affected(self):
        Scan.objects.create(
            name='done', target='203.0.113.1',
            status='completed',
            deadline=timezone.now() - timedelta(hours=1),
            created_by=self.owner,
        )
        from scanner.tasks import enforce_scan_deadlines
        result = enforce_scan_deadlines()
        self.assertEqual(result['cancelled'], 0)

    @patch('wireghost_web.celery.app')
    def test_duration_seconds_set_on_cancel(self, mock_celery):
        started = timezone.now() - timedelta(hours=1)
        scan = Scan.objects.create(
            name='timed', target='203.0.113.1',
            status='running', celery_task_id='task-t',
            deadline=timezone.now() - timedelta(minutes=5),
            started_at=started,
            created_by=self.owner,
        )
        from scanner.tasks import enforce_scan_deadlines
        enforce_scan_deadlines()
        scan.refresh_from_db()
        self.assertGreaterEqual(scan.duration_seconds, 3500)


class CalcNextRunTests(TestCase):
    def test_daily_advances_one_day(self):
        from scanner.tasks import _calc_next_run
        next_run = _calc_next_run('daily', dtime(2, 0))
        self.assertGreater(next_run, timezone.now())

    def test_weekly_advances_one_week(self):
        from scanner.tasks import _calc_next_run
        next_run = _calc_next_run('weekly', dtime(2, 0))
        self.assertGreater(next_run, timezone.now())
        within_8_days = timezone.now() + timedelta(days=8)
        self.assertLess(next_run, within_8_days)
