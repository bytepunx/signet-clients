"""Tests for signet_client.restart's AcquireLock/Lock state machine.

Ported from go/restart_test.go — same cases, same intent: drive the state
machine against hand-written fakes (tests/fakes.py), never a real gRPC
connection or signet instance.
"""

from __future__ import annotations

import datetime
import time

import pytest

from signet_client.errors import LockLostError, SignetError
from signet_client.restart import Lock, _acquire_lock_on_stream, acquire_lock

from .fakes import FakeLockStream, acquired_resp, queue_position_resp, ttl_extended_resp


def _utcnow_plus(seconds: float) -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=seconds)


class _ExplodingClient:
    """A client whose AcquireRestartLock() would blow up if ever called —
    used to prove ttl validation happens before any stream is opened.
    """

    def AcquireRestartLock(self, *args, **kwargs):
        raise AssertionError("AcquireRestartLock must not be called for an invalid ttl")


def test_acquire_lock_rejects_non_positive_ttl():
    with pytest.raises(ValueError, match=r"ttl_seconds must be > 0"):
        acquire_lock(_ExplodingClient(), "ns", "svc", 0)
    with pytest.raises(ValueError, match=r"ttl_seconds must be > 0"):
        acquire_lock(_ExplodingClient(), "ns", "svc", -1)


def test_acquire_lock_queue_position_then_acquired():
    stream = FakeLockStream()
    stream.push_response(queue_position_resp(2))
    stream.push_response(queue_position_resp(1))
    stream.push_response(acquired_resp("tok-1", _utcnow_plus(30)))

    lock = _acquire_lock_on_stream(stream, "ns", "svc", 4)
    try:
        assert lock.token == "tok-1"
        assert stream.sent_count() == 1, "expected exactly 1 initial send before heartbeats"
    finally:
        lock.release()


def test_acquire_lock_stream_error_before_acquired():
    stream = FakeLockStream()
    stream.push_error(RuntimeError("boom"))

    with pytest.raises(SignetError, match=r"stream failed before lock was acquired.*boom"):
        _acquire_lock_on_stream(stream, "ns", "svc", 4)


def test_acquire_lock_heartbeat_interval_is_ttl_over_four():
    stream = FakeLockStream()
    stream.push_response(acquired_resp("tok-1", _utcnow_plus(4)))

    # ttl=4s => heartbeat interval = 1s. Wait ~2.5s and expect >=2 heartbeats
    # sent (in addition to the 1 initial request).
    lock = _acquire_lock_on_stream(stream, "ns", "svc", 4)
    try:
        time.sleep(2.5)
        got = stream.sent_count()
        assert got >= 3, f"sentCount() = {got}, want >= 3 (1 initial + >=2 heartbeats at ~1s interval)"
    finally:
        lock.release()


def test_lock_ttl_extended_updates_expires_at():
    stream = FakeLockStream()
    first = _utcnow_plus(4)
    stream.push_response(acquired_resp("tok-1", first))

    lock = _acquire_lock_on_stream(stream, "ns", "svc", 4)
    try:
        extended = _utcnow_plus(60)
        stream.push_response(ttl_extended_resp(extended))

        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if lock.expires_at is not None and abs(
                (lock.expires_at - extended).total_seconds()
            ) < 0.001:
                break
            time.sleep(0.01)
        else:
            pytest.fail(
                f"expires_at never reflected TTL_EXTENDED; last={lock.expires_at}, want={extended}"
            )
    finally:
        lock.release()


def test_lock_release_is_idempotent():
    stream = FakeLockStream()
    stream.push_response(acquired_resp("tok-1", _utcnow_plus(30)))

    lock = _acquire_lock_on_stream(stream, "ns", "svc", 4)
    lock.release()
    lock.release()  # must not raise / hang


def test_lock_lost_reported_on_unexpected_stream_error():
    stream = FakeLockStream()
    stream.push_response(acquired_resp("tok-1", _utcnow_plus(4)))

    lock = _acquire_lock_on_stream(stream, "ns", "svc", 4)
    try:
        stream.push_error(RuntimeError("lock lost"))

        assert lock.lost_event.wait(timeout=2), "lost_event never set after stream error"
        assert lock.lost_error is not None
        assert isinstance(lock.lost_error, LockLostError)
        assert "lock lost" in str(lock.lost_error)
    finally:
        lock.release()


def test_lock_release_does_not_report_lost():
    stream = FakeLockStream()
    stream.push_response(acquired_resp("tok-1", _utcnow_plus(30)))

    lock = _acquire_lock_on_stream(stream, "ns", "svc", 4)
    lock.release()

    assert not lock.lost_event.wait(timeout=0.2), "lost_event fired after a clean release()"
    assert lock.lost_error is None


def test_lock_recv_thread_exits_after_release():
    """Deviation/addition beyond the Go suite: verify no thread leaks past
    release() — the recv thread must have actually terminated, not just
    signalled recv_done early.
    """
    stream = FakeLockStream()
    stream.push_response(acquired_resp("tok-1", _utcnow_plus(30)))

    lock = _acquire_lock_on_stream(stream, "ns", "svc", 4)
    lock.release()

    lock._recv_thread.join(timeout=2)
    assert not lock._recv_thread.is_alive()
    lock._heartbeat_thread.join(timeout=2)
    assert not lock._heartbeat_thread.is_alive()


def test_acquire_lock_wraps_dial_failure():
    """acquire_lock() (the public entrypoint, not the internal
    _acquire_lock_on_stream helper) must wrap a stream-open failure in a
    SignetError with context, not leak a bare/opaque exception.
    """

    class _BrokenClient:
        def AcquireRestartLock(self, *args, **kwargs):
            raise RuntimeError("connection refused")

    with pytest.raises(SignetError, match=r"open AcquireRestartLock stream.*connection refused"):
        acquire_lock(_BrokenClient(), "ns", "svc", 4)


def test_send_initial_request_failure_is_clear():
    class _FailOnSendStream:
        def send(self, request):
            raise RuntimeError("write failed")

        def recv(self):
            raise AssertionError("recv should not be called if send failed")

        def close_send(self):
            pass

    with pytest.raises(SignetError, match=r"send initial AcquireRestartLock request.*write failed"):
        _acquire_lock_on_stream(_FailOnSendStream(), "ns", "svc", 4)


def test_lock_context_manager_releases():
    stream = FakeLockStream()
    stream.push_response(acquired_resp("tok-1", _utcnow_plus(30)))

    lock = _acquire_lock_on_stream(stream, "ns", "svc", 4)
    with lock:
        assert lock.token == "tok-1"

    # released implicitly by __exit__; second explicit release is still a no-op
    lock.release()
