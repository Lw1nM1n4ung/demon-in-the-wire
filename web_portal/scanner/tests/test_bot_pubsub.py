import json
from unittest.mock import patch, MagicMock
from django.test import TestCase


def _mock_site_config():
    cfg = MagicMock()
    cfg.telegram_bot_token = 'fake:bot_token'
    cfg.telegram_shared_chat_id = ''
    return cfg


class TestPubSubNotificationPayload(TestCase):
    """Test the Redis pub/sub message format used by notifications.py.

    Verifies the serialization boundary between worker (publisher) and
    bot (subscriber). A format mismatch silently drops notifications.
    """

    @patch('scanner.notifications.redis_lib')
    @patch('scanner.notifications.send_telegram')
    @patch('scanner.models.SiteConfig.get')
    def test_pubsub_publishes_on_notify(self, mock_sc_get, mock_send_tg, mock_redis_lib):
        mock_sc_get.return_value = _mock_site_config()
        mock_conn = MagicMock()
        mock_redis_lib.Redis.from_url.return_value = mock_conn

        from scanner.notifications import notify

        mock_scan = MagicMock()
        mock_scan.id = '019dc3af-0000-0000-0000-000000000000'
        mock_scan.name = 'Test Scan'
        mock_scan.target = '192.168.1.0/24'
        mock_scan.status = 'completed'
        mock_scan.created_by = None

        notify('scan.complete', scan=mock_scan)

        assert mock_conn.publish.called, 'Redis publish was not called'
        channel, raw_payload = mock_conn.publish.call_args[0]
        assert channel == 'wireghost:bot:notify'
        data = json.loads(raw_payload)
        assert data['event'] == 'scan.complete'
        assert 'text' in data
        assert len(data['text']) > 0

    @patch('scanner.notifications.redis_lib')
    @patch('scanner.notifications.send_telegram')
    @patch('scanner.models.SiteConfig.get')
    def test_pubsub_includes_document_for_report_ready(self, mock_sc_get, mock_send_tg, mock_redis_lib):
        mock_sc_get.return_value = _mock_site_config()
        mock_conn = MagicMock()
        mock_redis_lib.Redis.from_url.return_value = mock_conn

        from scanner.notifications import notify

        mock_report_qs = MagicMock()
        mock_report_qs.filter.return_value.values_list.return_value = ['/data/output/report.docx']

        mock_scan = MagicMock()
        mock_scan.id = '019dc3af-0000-0000-0000-000000000001'
        mock_scan.name = 'Report Scan'
        mock_scan.target = '10.0.0.0/24'
        mock_scan.status = 'completed'
        mock_scan.created_by = None
        mock_scan.reports = mock_report_qs

        notify('report.ready', scan=mock_scan)

        assert mock_conn.publish.called
        data = json.loads(mock_conn.publish.call_args[0][1])
        assert data['event'] == 'report.ready'
        assert data.get('document_path') == '/data/output/report.docx'

    @patch('scanner.notifications.redis_lib')
    @patch('scanner.notifications.send_telegram')
    @patch('scanner.models.SiteConfig.get')
    def test_pubsub_failure_does_not_raise(self, mock_sc_get, mock_send_tg, mock_redis_lib):
        mock_sc_get.return_value = _mock_site_config()
        mock_redis_lib.Redis.from_url.side_effect = ConnectionError('Redis down')

        from scanner.notifications import notify

        mock_scan = MagicMock()
        mock_scan.id = '019dc3af-0000-0000-0000-000000000002'
        mock_scan.name = 'Fail Scan'
        mock_scan.target = '10.0.0.1'
        mock_scan.status = 'completed'
        mock_scan.created_by = None

        notify('scan.complete', scan=mock_scan)
