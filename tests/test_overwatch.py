"""Tests for the network overwatch detector."""

from __future__ import annotations

import asyncio

from wireghost.pipeline.overwatch import NetworkOverwatch, _TaskCancelled


class _FakePing:
    """Stub that replaces NetworkOverwatch.ping_host with controllable results.

    Values can be plain booleans or callables returning booleans, so tests
    can flip reachability mid-scan.
    """

    def __init__(self, results: dict[str, object] | None = None):
        self._results = dict(results or {})
        self.calls: list[str] = []

    async def __call__(self, ip: str) -> bool:
        self.calls.append(ip)
        result = self._results.get(ip, False)
        if callable(result):
            return result()
        return result


async def test_pauses_when_all_targets_fail():
    """All targets fail -> overwatch pauses."""
    fake = _FakePing({"8.8.8.8": False, "10.0.0.1": False})
    ow = NetworkOverwatch(
        targets=["8.8.8.8", "10.0.0.1"],
        fail_threshold=2,
        recover_threshold=2,
        interval=0.01,
        timeout=0.5,
    )
    ow.ping_host = fake  # type: ignore[method-assign]

    cancelled = False

    def is_aborted() -> bool:
        return cancelled

    # Run check with a timeout so the test doesn't hang forever if paused.
    try:
        await asyncio.wait_for(ow.check(is_aborted), timeout=1.0)
    except asyncio.TimeoutError:
        cancelled = True

    assert cancelled, "Expected pause (task would be cancelled)"

    # Both targets should have been pinged at least fail_threshold times.
    assert fake.calls.count("8.8.8.8") >= 2
    assert fake.calls.count("10.0.0.1") >= 2
    assert ow.is_paused


async def test_resumes_when_targets_recover():
    """All targets recover -> overwatch unpauses."""
    state = {"reachable": False}
    fake = _FakePing(
        {
            "8.8.8.8": lambda: state["reachable"],
            "10.0.0.1": lambda: state["reachable"],
        }
    )
    ow = NetworkOverwatch(
        targets=["8.8.8.8", "10.0.0.1"],
        fail_threshold=1,
        recover_threshold=2,
        interval=0.01,
        timeout=0.5,
    )
    ow.ping_host = fake  # type: ignore[method-assign]

    # First check: targets down -> pause
    try:
        await asyncio.wait_for(ow.check(lambda: False), timeout=1.0)
    except asyncio.TimeoutError:
        pass  # expected - paused

    assert ow.is_paused

    # Now targets come back up
    state["reachable"] = True

    # Should resume after recover_threshold consecutive successes
    await asyncio.wait_for(ow.check(lambda: False), timeout=1.0)
    assert not ow.is_paused


async def test_no_targets_no_pause():
    """Empty target list -> no overwatch, check returns immediately."""
    ow = NetworkOverwatch(targets=[], fail_threshold=3, interval=0.01)
    await ow.check(lambda: False)
    assert not ow.is_paused


async def test_missing_probe_binary_does_not_pause(monkeypatch):
    """No ping/fping binary -> overwatch is skipped instead of pausing forever.

    Without a probe binary every check fails, which is indistinguishable from
    a dead network.  Parking the scan in an endless pause would be worse than
    not overwatching at all.
    """
    monkeypatch.setattr("wireghost.pipeline.overwatch.shutil.which", lambda _: None)
    ow = NetworkOverwatch(targets=["8.8.8.8"], fail_threshold=1, interval=0.01)
    assert not ow.available
    # Must return promptly rather than entering the pause loop.
    await asyncio.wait_for(ow.check(lambda: False), timeout=1.0)
    assert not ow.is_paused


async def test_fping_counts_as_available(monkeypatch):
    """fping alone is enough — ping may not be installed in the image."""
    monkeypatch.setattr(
        "wireghost.pipeline.overwatch.shutil.which",
        lambda name: "/usr/bin/fping" if name == "fping" else None,
    )
    ow = NetworkOverwatch(targets=["8.8.8.8"], fail_threshold=1, interval=0.01)
    assert ow.available


def test_gateway_detection_falls_back_to_proc(monkeypatch):
    """/proc/net/route is parsed when iproute2 is not installed."""
    import io

    import wireghost.pipeline.overwatch as ow_mod

    monkeypatch.setattr(ow_mod.shutil, "which", lambda _: None)
    route_file = io.StringIO(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
        "eth0\t00000000\t0100A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
    )
    monkeypatch.setattr("builtins.open", lambda *a, **k: route_file)
    # 0100A8C0 little-endian -> 192.168.0.1
    assert ow_mod._detect_gateway_proc() == "192.168.0.1"


async def test_single_target_failure_pauses():
    """With one target, a single failure pauses (all-targets rule)."""
    fake = _FakePing({"8.8.8.8": False})
    ow = NetworkOverwatch(
        targets=["8.8.8.8"],
        fail_threshold=1,
        recover_threshold=1,
        interval=0.01,
        timeout=0.5,
    )
    ow.ping_host = fake  # type: ignore[method-assign]

    try:
        await asyncio.wait_for(ow.check(lambda: False), timeout=1.0)
    except asyncio.TimeoutError:
        pass  # expected - paused

    assert ow.is_paused


async def test_aborted_during_pause_raises():
    """Task cancelled during pause -> _TaskCancelled raised."""

    fake = _FakePing({"8.8.8.8": False})
    ow = NetworkOverwatch(
        targets=["8.8.8.8"],
        fail_threshold=1,
        interval=0.01,
        timeout=0.5,
    )
    ow.ping_host = fake  # type: ignore[method-assign]

    cancelled = False

    def is_aborted() -> bool:
        return cancelled

    try:
        # Start check (will pause), then cancel after a short delay.
        async def cancel_later():
            await asyncio.sleep(0.05)
            nonlocal cancelled
            cancelled = True

        asyncio.create_task(cancel_later())
        await ow.check(is_aborted)
    except _TaskCancelled:
        pass  # expected
    except asyncio.TimeoutError:
        raise AssertionError("Should have raised _TaskCancelled, not timed out")
