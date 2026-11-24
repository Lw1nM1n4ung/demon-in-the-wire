"""Tests for the cross-process report render lock."""

from __future__ import annotations

import threading
import time

from django.core.cache import cache
from django.test import TestCase

from scanner.tasks import _REPORT_LOCK_KEY, _report_render_lock


class ReportRenderLockTests(TestCase):
    def setUp(self):
        cache.delete(_REPORT_LOCK_KEY)

    def tearDown(self):
        cache.delete(_REPORT_LOCK_KEY)

    def test_lock_releases_after_render(self):
        with _report_render_lock():
            assert cache.get(_REPORT_LOCK_KEY) is not None
        assert cache.get(_REPORT_LOCK_KEY) is None

    def test_second_render_waits_for_the_first(self):
        order: list[str] = []

        def first():
            with _report_render_lock():
                order.append("first-in")
                time.sleep(0.4)
                order.append("first-out")

        def second():
            with _report_render_lock():
                order.append("second-in")
                order.append("second-out")

        t1 = threading.Thread(target=first)
        t1.start()
        time.sleep(0.1)
        t2 = threading.Thread(target=second)
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        assert order == ["first-in", "first-out", "second-in", "second-out"]

    def test_render_runs_even_if_lock_is_stuck(self):
        """A stale lock must not cost us the report."""
        from scanner import tasks

        cache.set(_REPORT_LOCK_KEY, "someone-else", timeout=600)
        original = tasks._REPORT_LOCK_WAIT
        tasks._REPORT_LOCK_WAIT = 0
        try:
            with _report_render_lock():
                pass
        finally:
            tasks._REPORT_LOCK_WAIT = original

        # The stale owner's token must survive; we did not take the lock.
        assert cache.get(_REPORT_LOCK_KEY) == "someone-else"
