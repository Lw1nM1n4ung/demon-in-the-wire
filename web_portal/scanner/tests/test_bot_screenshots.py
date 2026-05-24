import asyncio
import tempfile
import os
from pathlib import Path
from unittest import TestCase
from unittest.mock import AsyncMock, MagicMock, patch

from scanner.bot.screenshots import resolve_path, send_one, send_album


def run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TestResolvePath(TestCase):

    def test_null_output_dir_returns_none(self):
        ss = MagicMock()
        ss.scan.output_dir = None
        self.assertIsNone(resolve_path(ss))

    def test_empty_output_dir_returns_none(self):
        ss = MagicMock()
        ss.scan.output_dir = ''
        self.assertIsNone(resolve_path(ss))

    def test_traversal_attack_blocked(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            scan_dir = root / 'scans'
            scan_dir.mkdir()
            secret = root / 'secret.txt'
            secret.write_text('secret')
            ss = MagicMock()
            ss.scan.output_dir = str(scan_dir)
            ss.filename = '../secret.txt'
            result = resolve_path(ss)
            self.assertIsNone(result)

    def test_absolute_path_in_filename_blocked(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ss = MagicMock()
            ss.scan.output_dir = tmpdir
            ss.filename = '/etc/passwd'
            result = resolve_path(ss)
            self.assertIsNone(result)

    def test_valid_path_returned(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            img = Path(tmpdir) / 'screenshot.png'
            img.write_bytes(b'\x89PNG fake')
            ss = MagicMock()
            ss.scan.output_dir = tmpdir
            ss.filename = 'screenshot.png'
            result = resolve_path(ss)
            self.assertIsNotNone(result)
            self.assertEqual(result, img.resolve())

    def test_missing_file_returns_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ss = MagicMock()
            ss.scan.output_dir = tmpdir
            ss.filename = 'nonexistent.png'
            result = resolve_path(ss)
            self.assertIsNone(result)

    def test_double_dot_in_subdirectory_blocked(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sub = Path(tmpdir) / 'scans'
            sub.mkdir()
            ss = MagicMock()
            ss.scan.output_dir = str(sub)
            ss.filename = '../../etc/passwd'
            result = resolve_path(ss)
            self.assertIsNone(result)

    def test_symlink_escape_blocked(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / 'outside'
            target.mkdir()
            secret = target / 'secret.txt'
            secret.write_text('secret')
            scan_dir = Path(tmpdir) / 'scandir'
            scan_dir.mkdir()
            link = scan_dir / 'link.txt'
            try:
                link.symlink_to(secret)
            except OSError:
                self.skipTest('Cannot create symlinks')
            ss = MagicMock()
            ss.scan.output_dir = str(scan_dir)
            ss.filename = 'link.txt'
            result = resolve_path(ss)
            self.assertIsNone(result)


class TestSendOne(TestCase):

    def test_returns_false_when_path_unresolvable(self):
        bot = AsyncMock()
        ss = MagicMock()
        ss.scan.output_dir = None
        result = run_async(send_one(bot, 12345, ss))
        self.assertFalse(result)
        bot.send_photo.assert_not_called()

    def test_sends_photo_for_small_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            img = Path(tmpdir) / 'small.png'
            img.write_bytes(b'\x89PNG' + b'\x00' * 100)
            ss = MagicMock()
            ss.scan.output_dir = tmpdir
            ss.filename = 'small.png'
            bot = AsyncMock()
            result = run_async(send_one(bot, 12345, ss, 'caption'))
            self.assertTrue(result)
            bot.send_photo.assert_called_once()

    def test_sends_document_for_large_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            img = Path(tmpdir) / 'big.png'
            img.write_bytes(b'\x89PNG' + b'\x00' * (6 * 1024 * 1024))
            ss = MagicMock()
            ss.scan.output_dir = tmpdir
            ss.filename = 'big.png'
            bot = AsyncMock()
            result = run_async(send_one(bot, 12345, ss))
            self.assertTrue(result)
            bot.send_document.assert_called_once()


class TestSendAlbum(TestCase):

    def test_empty_list_returns_zero(self):
        bot = AsyncMock()
        result = run_async(send_album(bot, 12345, []))
        self.assertEqual(result, 0)

    def test_no_resolvable_screenshots_returns_zero(self):
        bot = AsyncMock()
        ss = MagicMock()
        ss.scan.output_dir = None
        result = run_async(send_album(bot, 12345, [ss]))
        self.assertEqual(result, 0)
        bot.send_media_group.assert_not_called()

    def test_sends_album_with_valid_screenshots(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            screenshots = []
            for i in range(3):
                img = Path(tmpdir) / f'ss{i}.png'
                img.write_bytes(b'\x89PNG' + b'\x00' * 100)
                ss = MagicMock()
                ss.scan.output_dir = tmpdir
                ss.filename = f'ss{i}.png'
                ss.id = i
                screenshots.append(ss)
            bot = AsyncMock()
            result = run_async(send_album(bot, 12345, screenshots, 'Test'))
            self.assertEqual(result, 3)
            bot.send_media_group.assert_called_once()
