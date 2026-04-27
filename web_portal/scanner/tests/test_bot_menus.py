from unittest import TestCase

from scanner.bot.menus import (
    PAGE_SIZE,
    main_menu_kb,
    scan_list_kb,
    scan_detail_kb,
    finding_filter_kb,
    findings_list_kb,
    asset_list_kb,
    asset_detail_kb,
    schedule_list_kb,
    schedule_detail_kb,
    photo_list_kb,
    new_scan_kb,
    confirm_cancel_kb,
)


def _all_callback_data(kb):
    results = []
    for row in kb.inline_keyboard:
        for btn in row:
            if btn.callback_data:
                results.append(btn.callback_data)
    return results


class TestCallbackDataSize(TestCase):
    """Telegram enforces a hard 64-byte limit on callback_data."""

    def _assert_all_under_64(self, kb, label=''):
        for cd in _all_callback_data(kb):
            self.assertLessEqual(
                len(cd.encode('utf-8')), 64,
                f'{label} callback_data too long ({len(cd.encode("utf-8"))}B): {cd!r}',
            )

    def test_main_menu_owner(self):
        self._assert_all_under_64(main_menu_kb('owner'), 'main_menu owner')

    def test_scan_list(self):
        scans = [
            ('a1b2c3d4-0000-0000-0000-000000000000', '192.168.1.0/24', 'completed', 'full', 5, None),
        ]
        self._assert_all_under_64(scan_list_kb(scans, 0, 10), 'scan_list')

    def test_scan_detail_worst_case(self):
        self._assert_all_under_64(scan_detail_kb('a1b2c3d4', 'running', True), 'scan_detail')

    def test_finding_filter_with_scan(self):
        self._assert_all_under_64(finding_filter_kb('a1b2c3d4'), 'finding_filter scan')

    def test_finding_filter_global(self):
        self._assert_all_under_64(finding_filter_kb(), 'finding_filter global')

    def test_findings_list_with_scan(self):
        self._assert_all_under_64(findings_list_kb(5, 10, 'critical', 'a1b2c3d4'), 'findings_list scan')

    def test_findings_list_global(self):
        self._assert_all_under_64(findings_list_kb(5, 10, 'critical'), 'findings_list global')

    def test_photo_list(self):
        self._assert_all_under_64(photo_list_kb('a1b2c3d4', 10, 0, 3), 'photo_list')

    def test_schedule_list(self):
        scheds = [
            ('a1b2c3d4-0000-0000-0000-000000000000', 'Nightly', '10.0.0.0/24', True, 'daily', None, None, 'full'),
        ]
        self._assert_all_under_64(schedule_list_kb(scheds, 0, 5), 'schedule_list')

    def test_schedule_detail(self):
        self._assert_all_under_64(schedule_detail_kb('a1b2c3d4', True), 'schedule_detail')

    def test_new_scan(self):
        self._assert_all_under_64(new_scan_kb(), 'new_scan')

    def test_confirm_cancel(self):
        self._assert_all_under_64(confirm_cancel_kb('a1b2c3d4'), 'confirm_cancel')

    def test_asset_list(self):
        assets = [
            ('a1b2c3d4-0000-0000-0000-000000000000', '10.0.0.1', 'web.local', 'http', 85, 3, 1, 1, None),
        ]
        self._assert_all_under_64(asset_list_kb(assets, 0, 5), 'asset_list')

    def test_asset_detail(self):
        self._assert_all_under_64(asset_detail_kb('a1b2c3d4'), 'asset_detail')


class TestMainMenuRoles(TestCase):

    def test_viewer_gets_3_rows(self):
        kb = main_menu_kb('viewer')
        self.assertEqual(len(kb.inline_keyboard), 3)

    def test_engineer_gets_4_rows(self):
        kb = main_menu_kb('engineer')
        self.assertEqual(len(kb.inline_keyboard), 4)

    def test_owner_gets_5_rows(self):
        kb = main_menu_kb('owner')
        self.assertEqual(len(kb.inline_keyboard), 5)

    def test_owner_has_health_button(self):
        kb = main_menu_kb('owner')
        all_data = _all_callback_data(kb)
        self.assertIn('hl', all_data)
        self.assertIn('cf', all_data)

    def test_owner_has_users_button(self):
        kb = main_menu_kb('owner')
        all_data = _all_callback_data(kb)
        self.assertIn('ul:0', all_data)

    def test_all_roles_have_help(self):
        for role in ('viewer', 'engineer', 'owner'):
            kb = main_menu_kb(role)
            all_data = _all_callback_data(kb)
            self.assertIn('hp', all_data, f'{role} missing help button')

    def test_viewer_no_admin_buttons(self):
        kb = main_menu_kb('viewer')
        all_data = _all_callback_data(kb)
        self.assertNotIn('hl', all_data)
        self.assertNotIn('cf', all_data)
        self.assertNotIn('cl:0', all_data)
        self.assertNotIn('ul:0', all_data)


class TestScanDetailKb(TestCase):

    def test_completed_has_report(self):
        kb = scan_detail_kb('abc12345', 'completed', False)
        all_data = _all_callback_data(kb)
        self.assertTrue(any(d.startswith('sr:') for d in all_data))

    def test_completed_no_cancel(self):
        kb = scan_detail_kb('abc12345', 'completed', False)
        all_data = _all_callback_data(kb)
        self.assertFalse(any(d.startswith('sx:') for d in all_data))

    def test_running_has_cancel(self):
        kb = scan_detail_kb('abc12345', 'running', False)
        all_data = _all_callback_data(kb)
        self.assertTrue(any(d.startswith('sx:') for d in all_data))

    def test_running_no_report(self):
        kb = scan_detail_kb('abc12345', 'running', False)
        all_data = _all_callback_data(kb)
        self.assertFalse(any(d.startswith('sr:') for d in all_data))

    def test_screenshots_conditional(self):
        kb_no = scan_detail_kb('abc12345', 'completed', False)
        kb_yes = scan_detail_kb('abc12345', 'completed', True)
        data_no = _all_callback_data(kb_no)
        data_yes = _all_callback_data(kb_yes)
        self.assertFalse(any(d.startswith('sp:') for d in data_no))
        self.assertTrue(any(d.startswith('sp:') for d in data_yes))

    def test_always_has_findings(self):
        kb = scan_detail_kb('abc12345', 'pending', False)
        all_data = _all_callback_data(kb)
        self.assertTrue(any(d.startswith('sf:') for d in all_data))

    def test_always_has_back(self):
        kb = scan_detail_kb('abc12345', 'running', False)
        all_data = _all_callback_data(kb)
        self.assertIn('sl:0', all_data)


class TestPagination(TestCase):

    SAMPLE_ASSETS = [
        ('a1b2c3d4-0000-0000-0000-000000000000', '10.0.0.1', 'web.local', 'http', 85, 3, 1, 1, None),
    ]

    def test_first_page_no_prev(self):
        kb = asset_list_kb(self.SAMPLE_ASSETS, 0, 5)
        all_data = _all_callback_data(kb)
        for d in all_data:
            if d.startswith('al:'):
                page_num = int(d.split(':')[1])
                self.assertGreaterEqual(page_num, 0)

    def test_last_page_no_next(self):
        kb = asset_list_kb(self.SAMPLE_ASSETS, 4, 5)
        all_data = _all_callback_data(kb)
        self.assertNotIn('al:5', all_data)

    def test_middle_page_has_both(self):
        kb = asset_list_kb(self.SAMPLE_ASSETS, 2, 5)
        all_data = _all_callback_data(kb)
        self.assertIn('al:1', all_data)
        self.assertIn('al:3', all_data)

    def test_single_page_no_nav(self):
        kb = asset_list_kb(self.SAMPLE_ASSETS, 0, 1)
        all_data = _all_callback_data(kb)
        self.assertNotIn('al:1', all_data)

    def test_asset_rows_are_clickable(self):
        kb = asset_list_kb(self.SAMPLE_ASSETS, 0, 1)
        all_data = _all_callback_data(kb)
        self.assertTrue(any(d.startswith('ad:') for d in all_data))


class TestPhotoListKb(TestCase):

    def test_send_all_when_photos_exist(self):
        kb = photo_list_kb('abc12345', 5, 0, 2)
        all_data = _all_callback_data(kb)
        self.assertTrue(any('all' in d for d in all_data))

    def test_no_send_all_when_empty(self):
        kb = photo_list_kb('abc12345', 0, 0, 1)
        all_data = _all_callback_data(kb)
        self.assertFalse(any('all' in d for d in all_data))


class TestNewScanKb(TestCase):

    def test_has_all_scan_types(self):
        kb = new_scan_kb()
        all_data = _all_callback_data(kb)
        for stype in ('full', 'quick', 'port', 'web', 'service'):
            self.assertIn(f'ns:{stype}', all_data)

    def test_has_back_to_menu(self):
        kb = new_scan_kb()
        all_data = _all_callback_data(kb)
        self.assertIn('mn', all_data)
