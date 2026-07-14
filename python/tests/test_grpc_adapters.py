"""Tests for the _GrpcLockStream / _GrpcWatchStream adapters, and the public
watch_bundle()/acquire_lock() entry points that use them.

tests/test_lock.py and tests/test_watch.py drive the state machines
(_acquire_lock_on_stream, _watch_loop) directly against hand-written fakes
that implement the LockStream/WatchStream protocol, exactly mirroring
go/restart_test.go. Those tests never exercise the adapter classes that
bridge grpc-python's bidi-streaming API (a single request *iterator*, no
imperative send()) to that protocol — this file covers that bridge
specifically, since it's the one piece of genuinely novel concurrency logic
that isn't a port of anything in the Go client (Go's generated stub already
exposes an imperative Send/Recv stream).

Still no live network connection: the fakes here stand in for exactly what
a grpc stub call object looks like (an iterator of responses, consuming a
request iterator on the way in), not a real channel.
"""

from __future__ import annotations

import queue
import threading
import time

import pytest

from signet.v1 import secrets_pb2 as pb
from signet_client.errors import SignetError
from signet_client.restart import (
    _GrpcLockStream,
    _GrpcWatchStream,
    acquire_lock,
    watch_bundle,
)


class _FakeGrpcBidiCall:
    """Mimics what a real grpc stub's stream_stream(...) call looks like:
    an iterator of responses, plus something that drains the request
    iterator passed in (as grpc-core does internally) on a background
    thread and records what it read.
    """

    def __init__(self, request_iterator) -> None:
        self.sent = []
        self._responses: "queue.Queue[object]" = queue.Queue()
        self._sentinel = object()
        self._reader_thread = threading.Thread(
            target=self._drain, args=(request_iterator,), daemon=True
        )
        self._reader_thread.start()

    def _drain(self, request_iterator) -> None:
        for item in request_iterator:
            self.sent.append(item)
        # Mirrors a real signet server: once it observes the client half-close
        # its write side (request_iterator exhausted, i.e. close_send() was
        # called), it ends its own response stream too (restart-lock.md:
        # "close stream -> lock released, next waiter notified"). Without
        # this, recv() would block forever and Lock.release() (which waits
        # for the recv loop to observe the close) would hang.
        self.close_responses()

    def push_response(self, resp) -> None:
        self._responses.put(resp)

    def close_responses(self) -> None:
        self._responses.put(self._sentinel)

    def __iter__(self):
        return self

    def __next__(self):
        item = self._responses.get()
        if item is self._sentinel:
            raise StopIteration
        return item


class _FakeSecretsStub:
    def __init__(self) -> None:
        self.lock_calls = []
        self.watch_requests = []
        self._watch_calls: "queue.Queue[_FakeWatchCall]" = queue.Queue()

    def AcquireRestartLock(self, request_iterator):
        call = _FakeGrpcBidiCall(request_iterator)
        self.lock_calls.append(call)
        return call

    def WatchServiceBundle(self, request):
        self.watch_requests.append(request)
        call = _FakeWatchCall()
        self._watch_calls.put(call)
        return call

    def next_watch_call(self, timeout=2):
        return self._watch_calls.get(timeout=timeout)


class _FakeWatchCall:
    def __init__(self) -> None:
        self._responses: "queue.Queue[object]" = queue.Queue()
        self._sentinel = object()
        self.cancelled = False

    def push(self, resp) -> None:
        self._responses.put(resp)

    def close(self) -> None:
        self._responses.put(self._sentinel)

    def __iter__(self):
        return self

    def __next__(self):
        item = self._responses.get()
        if item is self._sentinel:
            raise StopIteration
        return item

    def cancel(self) -> None:
        self.cancelled = True
        self.close()


def _wait_until(predicate, timeout=2.0, interval=0.005):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


# --- _GrpcLockStream ---


def test_grpc_lock_stream_send_reaches_the_call():
    stub = _FakeSecretsStub()
    stream = _GrpcLockStream(stub)
    req = pb.AcquireRestartLockRequest(namespace="ns", service="svc", ttl_seconds=4)
    stream.send(req)

    call = stub.lock_calls[0]
    assert _wait_until(lambda: len(call.sent) == 1)
    assert call.sent == [req]


def test_grpc_lock_stream_recv_returns_pushed_response():
    stub = _FakeSecretsStub()
    stream = _GrpcLockStream(stub)
    stream.send(pb.AcquireRestartLockRequest(namespace="ns", service="svc", ttl_seconds=4))

    resp = pb.AcquireRestartLockResponse(
        message_type=pb.AcquireRestartLockResponse.MESSAGE_TYPE_ACQUIRED, token="tok"
    )
    stub.lock_calls[0].push_response(resp)
    assert stream.recv() == resp


def test_grpc_lock_stream_close_send_ends_request_generator():
    stub = _FakeSecretsStub()
    stream = _GrpcLockStream(stub)
    stream.send(pb.AcquireRestartLockRequest(namespace="ns", service="svc", ttl_seconds=1))
    stream.close_send()

    call = stub.lock_calls[0]
    call._reader_thread.join(timeout=2)
    assert not call._reader_thread.is_alive(), "close_send() should end the request generator"
    assert len(call.sent) == 1


def test_grpc_lock_stream_recv_raises_clear_error_on_server_close():
    stub = _FakeSecretsStub()
    stream = _GrpcLockStream(stub)
    stream.send(pb.AcquireRestartLockRequest(namespace="ns", service="svc", ttl_seconds=1))
    stub.lock_calls[0].close_responses()

    with pytest.raises(SignetError, match="closed by server"):
        stream.recv()


# --- _GrpcWatchStream ---


def test_grpc_watch_stream_recv_returns_pushed_response():
    call = _FakeWatchCall()
    stream = _GrpcWatchStream(call)
    resp = pb.WatchServiceBundleResponse(
        event_type=pb.WatchServiceBundleResponse.EVENT_TYPE_CHANGED
    )
    call.push(resp)
    assert stream.recv() == resp


def test_grpc_watch_stream_recv_raises_clear_error_on_server_close():
    call = _FakeWatchCall()
    stream = _GrpcWatchStream(call)
    call.close()
    with pytest.raises(SignetError, match="closed by server"):
        stream.recv()


def test_grpc_watch_stream_cancel_delegates_to_call():
    call = _FakeWatchCall()
    stream = _GrpcWatchStream(call)
    stream.cancel()
    assert call.cancelled


# --- public entry points: watch_bundle() / acquire_lock() end to end ---


def test_watch_bundle_public_api_end_to_end():
    stub = _FakeSecretsStub()
    watch = watch_bundle(stub, "ns", "svc")
    try:
        call = stub.next_watch_call()
        call.push(
            pb.WatchServiceBundleResponse(
                event_type=pb.WatchServiceBundleResponse.EVENT_TYPE_CHANGED
            )
        )
        assert watch.wait_for_change(timeout=2) is True
    finally:
        watch.close(timeout=2)

    assert stub.watch_requests[0].namespace == "ns"
    assert stub.watch_requests[0].service == "svc"


def test_acquire_lock_public_api_end_to_end():
    stub = _FakeSecretsStub()
    result: dict = {}

    def run():
        result["lock"] = acquire_lock(stub, "ns", "svc", 4)

    t = threading.Thread(target=run, daemon=True)
    t.start()

    assert _wait_until(lambda: len(stub.lock_calls) == 1)
    call = stub.lock_calls[0]
    assert _wait_until(lambda: len(call.sent) == 1)
    assert call.sent[0].namespace == "ns"
    assert call.sent[0].service == "svc"
    assert call.sent[0].ttl_seconds == 4

    call.push_response(
        pb.AcquireRestartLockResponse(
            message_type=pb.AcquireRestartLockResponse.MESSAGE_TYPE_ACQUIRED,
            token="tok-e2e",
        )
    )
    t.join(timeout=2)

    lock = result["lock"]
    assert lock.token == "tok-e2e"
    lock.release()
