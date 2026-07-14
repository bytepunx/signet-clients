"""Tests for wait_for_restart: WatchBundle + debounce + AcquireLock.

Drives the debounce logic at the unit level by substituting watch_bundle()
and acquire_lock() (monkeypatched at the module level) with lightweight
test doubles — the underlying watch/lock machinery already has its own
thorough coverage in test_watch.py / test_lock.py / test_grpc_adapters.py.
This file is specifically about wait_for_restart's own orchestration logic:
debounce coalescing, not refetching the bundle, and always closing the
watch afterwards.
"""

from __future__ import annotations

import threading
import time

import signet_client.restart as restart_mod
from signet_client.restart import wait_for_restart


class _FakeWatch:
    """wait_for_change() pops from a pre-seeded queue of "change" events
    (each represented by a short simulated delay), returning False once
    exhausted for at least `timeout` seconds — modeling "no further change
    arrived within the debounce window."
    """

    def __init__(self, num_changes: int) -> None:
        self._remaining = num_changes
        self.closed = False
        self.close_calls = 0

    def wait_for_change(self, timeout=None) -> bool:
        if self._remaining > 0:
            self._remaining -= 1
            time.sleep(0.01)
            return True
        if timeout:
            time.sleep(min(timeout, 0.05))
        return False

    def close(self, timeout=None) -> None:
        self.closed = True
        self.close_calls += 1


def test_wait_for_restart_debounces_rapid_changes(monkeypatch):
    fake_watch = _FakeWatch(num_changes=3)
    monkeypatch.setattr(
        restart_mod, "watch_bundle", lambda client, ns, svc: fake_watch
    )

    calls = []
    sentinel_lock = object()

    def fake_acquire_lock(client, ns, svc, ttl_seconds):
        calls.append((ns, svc, ttl_seconds))
        return sentinel_lock

    monkeypatch.setattr(restart_mod, "acquire_lock", fake_acquire_lock)

    result = wait_for_restart(
        None, "ns", "svc", ttl_seconds=30, debounce_seconds=0.05
    )

    assert result is sentinel_lock
    assert calls == [("ns", "svc", 30)], "acquire_lock should be called exactly once, after debounce settles"
    assert fake_watch.closed is True, "watch must always be closed, even on the success path"


def test_wait_for_restart_zero_debounce_acts_immediately(monkeypatch):
    fake_watch = _FakeWatch(num_changes=1)
    monkeypatch.setattr(
        restart_mod, "watch_bundle", lambda client, ns, svc: fake_watch
    )

    calls = []

    def fake_acquire_lock(client, ns, svc, ttl_seconds):
        calls.append(True)
        return "lock"

    monkeypatch.setattr(restart_mod, "acquire_lock", fake_acquire_lock)

    wait_for_restart(None, "ns", "svc", ttl_seconds=30, debounce_seconds=0)

    assert calls == [True]
    assert fake_watch.closed is True


def test_wait_for_restart_closes_watch_even_if_acquire_lock_raises(monkeypatch):
    fake_watch = _FakeWatch(num_changes=1)
    monkeypatch.setattr(
        restart_mod, "watch_bundle", lambda client, ns, svc: fake_watch
    )

    def fake_acquire_lock(client, ns, svc, ttl_seconds):
        raise RuntimeError("boom")

    monkeypatch.setattr(restart_mod, "acquire_lock", fake_acquire_lock)

    try:
        wait_for_restart(None, "ns", "svc", ttl_seconds=30, debounce_seconds=0)
    except RuntimeError:
        pass

    assert fake_watch.closed is True, "watch must be closed even when acquire_lock fails"


def test_wait_for_restart_does_not_fetch_bundle(monkeypatch):
    """Design-constraint regression test: wait_for_restart must not call
    anything resembling GetServiceBundle — the whole point is that the
    *next* process instance fetches fresh config during its own startup,
    not this one, since there's no replacement process to hand it to.
    """
    fake_watch = _FakeWatch(num_changes=1)
    monkeypatch.setattr(
        restart_mod, "watch_bundle", lambda client, ns, svc: fake_watch
    )
    monkeypatch.setattr(restart_mod, "acquire_lock", lambda client, ns, svc, ttl: "lock")

    class _ClientThatExplodesOnBundleFetch:
        def GetServiceBundle(self, *args, **kwargs):
            raise AssertionError("wait_for_restart must never fetch the bundle")

        def __getattr__(self, name):
            raise AssertionError(f"unexpected client method called: {name}")

    wait_for_restart(
        _ClientThatExplodesOnBundleFetch(), "ns", "svc", ttl_seconds=30, debounce_seconds=0
    )
