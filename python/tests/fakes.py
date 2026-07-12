"""Hand-written fakes for the LockStream / WatchStream protocols, mirroring
go/restart_test.go's fakeLockStream / fakeWatchStream. These drive the state
machines in signet_client.restart directly — no real gRPC connection or
signet instance involved anywhere in the test suite.
"""

from __future__ import annotations

import queue
import threading
from typing import List, Optional

from signet.v1 import secrets_pb2 as pb


class FakeLockStream:
    """A scripted lockStream: Recv() replays a queue of responses/errors fed
    via push_response/push_error; Send() records every request sent, for
    assertions; CloseSend() ends the response queue (further Recv() calls
    see "stream closed").
    """

    def __init__(self) -> None:
        self._responses: "queue.Queue[tuple]" = queue.Queue()
        self._closed_sentinel = object()
        self._lock = threading.Lock()
        self._sent: List[pb.AcquireRestartLockRequest] = []
        self._closed = False

    def push_response(self, resp: pb.AcquireRestartLockResponse) -> None:
        self._responses.put(("resp", resp))

    def push_error(self, err: BaseException) -> None:
        self._responses.put(("err", err))

    def send(self, request: pb.AcquireRestartLockRequest) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("send on closed stream")
            self._sent.append(request)

    def recv(self) -> pb.AcquireRestartLockResponse:
        item = self._responses.get()
        if item is self._closed_sentinel:
            raise RuntimeError("stream closed")
        kind, payload = item
        if kind == "err":
            raise payload
        return payload

    def close_send(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._responses.put(self._closed_sentinel)

    def sent_count(self) -> int:
        with self._lock:
            return len(self._sent)

    def sent_requests(self) -> List[pb.AcquireRestartLockRequest]:
        with self._lock:
            return list(self._sent)


def acquired_resp(token: str, expires_at=None) -> pb.AcquireRestartLockResponse:
    resp = pb.AcquireRestartLockResponse(
        message_type=pb.AcquireRestartLockResponse.MESSAGE_TYPE_ACQUIRED,
        token=token,
    )
    if expires_at is not None:
        resp.expires_at.FromDatetime(expires_at)
    return resp


def queue_position_resp(position: int) -> pb.AcquireRestartLockResponse:
    return pb.AcquireRestartLockResponse(
        message_type=pb.AcquireRestartLockResponse.MESSAGE_TYPE_QUEUE_POSITION,
        position=position,
    )


def ttl_extended_resp(expires_at) -> pb.AcquireRestartLockResponse:
    resp = pb.AcquireRestartLockResponse(
        message_type=pb.AcquireRestartLockResponse.MESSAGE_TYPE_TTL_EXTENDED,
    )
    resp.expires_at.FromDatetime(expires_at)
    return resp


class FakeWatchStream:
    """A scripted watchStream: Recv() replays a queue of responses/errors."""

    def __init__(self) -> None:
        self._responses: "queue.Queue[tuple]" = queue.Queue()
        self._closed_sentinel = object()
        self._lock = threading.Lock()
        self._recv_count = 0

    def push_changed(self) -> None:
        self._responses.put(
            (
                "resp",
                pb.WatchServiceBundleResponse(
                    event_type=pb.WatchServiceBundleResponse.EVENT_TYPE_CHANGED
                ),
            )
        )

    def push_error(self, err: BaseException) -> None:
        self._responses.put(("err", err))

    def recv(self) -> pb.WatchServiceBundleResponse:
        with self._lock:
            self._recv_count += 1
        item = self._responses.get()
        if item is self._closed_sentinel:
            raise RuntimeError("stream closed")
        kind, payload = item
        if kind == "err":
            raise payload
        return payload

    def recv_calls(self) -> int:
        with self._lock:
            return self._recv_count

    def cancel(self) -> None:
        """Unblocks a pending recv() the way a real gRPC call.cancel() would
        — used by tests that exercise Watch.close()'s cancellation path.
        """
        self._responses.put(self._closed_sentinel)
