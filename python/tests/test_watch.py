"""Tests for signet_client.restart's WatchBundle reconnect/coalescing loop.

Ported from go/restart_test.go — drives `_watch_loop` directly against
hand-written fakes, exactly like the Go test drives `watchLoop`.
"""

from __future__ import annotations

import queue
import threading
import time

from signet_client.restart import Watch, _StreamHolder, _watch_loop

from .fakes import FakeWatchStream


def test_watch_loop_coalesces_rapid_changes():
    # 3 changes are pushed but the response queue is never "closed" (no
    # sentinel), so after they're drained the 4th recv() call just blocks —
    # no error, no reconnect, so open_stream is only ever called once.
    stream = FakeWatchStream()
    stream.push_changed()
    stream.push_changed()
    stream.push_changed()

    changes: "queue.Queue[bool]" = queue.Queue(maxsize=1)
    stop_event = threading.Event()

    thread = threading.Thread(
        target=_watch_loop, args=(lambda: stream, changes, stop_event), daemon=True
    )
    thread.start()
    try:
        # Wait until the loop has actually drained all 3 pushed events (the
        # 4th recv() call is the one that blocks) before checking coalescing
        # — otherwise this is racy: consuming the first signal before all 3
        # are processed just frees the buffer for a legitimately new one.
        deadline = time.monotonic() + 2
        while stream.recv_calls() < 4 and time.monotonic() < deadline:
            time.sleep(0.005)
        assert stream.recv_calls() >= 4, (
            f"watch loop only issued {stream.recv_calls()} recv calls, want >= 4"
        )

        assert changes.qsize() == 1, "expected exactly 1 coalesced pending signal"

        changes.get_nowait()
        assert changes.empty(), "expected no further pending signal after draining the coalesced one"
    finally:
        stop_event.set()


def test_watch_loop_reconnects_after_stream_error():
    first = FakeWatchStream()
    first.push_error(RuntimeError("boom"))

    second = FakeWatchStream()
    second.push_changed()

    attempts = {"n": 0}
    lock = threading.Lock()

    def open_stream():
        with lock:
            attempts["n"] += 1
            n = attempts["n"]
        return first if n == 1 else second

    changes: "queue.Queue[bool]" = queue.Queue(maxsize=1)
    stop_event = threading.Event()

    thread = threading.Thread(
        target=_watch_loop, args=(open_stream, changes, stop_event), daemon=True
    )
    thread.start()
    try:
        got = changes.get(timeout=4)
        assert got is True
    finally:
        stop_event.set()


def test_watch_loop_backoff_on_repeated_open_failure(monkeypatch):
    """Addition beyond the Go suite: verify open_stream failures also go
    through the backoff sleep (not a hot retry loop) by monkeypatching the
    backoff floor down so the test stays fast while still asserting the
    sleep actually happened between attempts.
    """
    import signet_client.restart as restart_mod

    monkeypatch.setattr(restart_mod, "_WATCH_BACKOFF_MIN", 0.05)
    monkeypatch.setattr(restart_mod, "_WATCH_BACKOFF_MAX", 0.2)

    attempts = {"n": 0, "times": []}

    def open_stream():
        attempts["n"] += 1
        attempts["times"].append(time.monotonic())
        if attempts["n"] < 3:
            raise RuntimeError("still down")
        stream = FakeWatchStream()
        stream.push_changed()
        return stream

    changes: "queue.Queue[bool]" = queue.Queue(maxsize=1)
    stop_event = threading.Event()

    thread = threading.Thread(
        target=restart_mod._watch_loop, args=(open_stream, changes, stop_event), daemon=True
    )
    thread.start()
    try:
        assert changes.get(timeout=4) is True
        assert attempts["n"] >= 3
        gaps = [b - a for a, b in zip(attempts["times"], attempts["times"][1:])]
        assert all(g >= 0.04 for g in gaps), f"expected backoff between retries, got gaps={gaps}"
    finally:
        stop_event.set()


def test_watch_public_wrapper_wait_for_change_and_close():
    """Exercises the public Watch wrapper (not just the internal
    _watch_loop) end to end against a fake stream factory. Wires up a
    _StreamHolder (as watch_bundle() does for real streams) so close() can
    unblock the background thread's in-flight, otherwise-blocking recv()
    call — proving Watch.close() actually terminates the thread promptly
    rather than leaking it.
    """
    stream = FakeWatchStream()
    stream.push_changed()
    holder = _StreamHolder()

    def open_stream():
        holder.set(stream)
        return stream

    watch = Watch(open_stream, holder=holder)
    try:
        assert watch.wait_for_change(timeout=2) is True
        assert watch.wait_for_change(timeout=0.2) is False
    finally:
        watch.close(timeout=2)

    assert not watch._thread.is_alive()


def test_watch_context_manager_closes():
    stream = FakeWatchStream()
    stream.push_changed()
    holder = _StreamHolder()

    def open_stream():
        holder.set(stream)
        return stream

    with Watch(open_stream, holder=holder) as watch:
        assert watch.wait_for_change(timeout=2) is True

    assert not watch._thread.is_alive()
