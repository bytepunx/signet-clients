"""Coordinated-restart support: WatchBundle, AcquireLock/Lock, WaitForRestart.

Python port of ``go/restart.go``. See ``python/README.md``'s "Coordinated
restarts" section and https://github.com/bytepunx/signet/blob/main/docs/restart-lock.md
for the protocol and design rationale — in short: this library never spawns
or supervises a child process, never writes the bundle to the environment or
disk, never refetches the bundle after acquiring the lock, and never calls
``sys.exit()`` itself. The caller decides when to actually terminate.

Concurrency model: synchronous ``grpc`` (not ``grpc.aio``), with a background
daemon thread doing the blocking read loop for each of the watch stream and
the lock stream — mirroring the Go client's one-goroutine-per-stream design.
A single background thread owns ``Recv()`` for a stream's entire lifetime so
that (a) unsolicited server messages (``TTL_EXTENDED`` acks, bundle-changed
events) are observed as they arrive rather than only in response to a client
read, and (b) a stream error or server-initiated close is detected promptly
as lock loss / a watch disconnect, rather than only being noticed the next
time the caller happens to call in.
"""

from __future__ import annotations

import queue
import threading
from datetime import datetime, timezone
from typing import Callable, Optional, Protocol

from signet.v1 import secrets_pb2 as pb

from .errors import LockLostError, SignetError

__all__ = [
    "Lock",
    "Watch",
    "acquire_lock",
    "watch_bundle",
    "wait_for_restart",
]

_WATCH_BACKOFF_MIN = 1.0
_WATCH_BACKOFF_MAX = 30.0


# --- Narrow protocols the state machines depend on, so tests can substitute
# hand-written fakes instead of a real gRPC stream. Mirrors go/restart.go's
# unexported lockStream/watchStream interfaces. ---


class LockStream(Protocol):
    def send(self, request: pb.AcquireRestartLockRequest) -> None: ...

    def recv(self) -> pb.AcquireRestartLockResponse: ...

    def close_send(self) -> None: ...


class WatchStream(Protocol):
    def recv(self) -> pb.WatchServiceBundleResponse: ...


# =====================================================================
# AcquireLock / Lock
# =====================================================================


class Lock:
    """A held signet restart lock.

    Call :meth:`release` (or use as a context manager) once your own
    graceful shutdown — draining in-flight work, closing resources — is
    complete, immediately before your process exits.

    ``lost_event`` is set, at most once, if the lock is lost unexpectedly
    (stream error, or the server closing the stream) before ``release`` is
    called; ``lost_error`` then holds the triggering exception. Treat this as
    "another replica may now acquire and restart concurrently" — there is
    nothing to undo, only to log.
    """

    def __init__(self, stream: LockStream) -> None:
        self._stream = stream
        self._mu = threading.Lock()
        self._token = ""
        self._expires_at: Optional[datetime] = None
        self._released = False

        self.lost_event = threading.Event()
        self.lost_error: Optional[BaseException] = None

        self._heartbeat_stop = threading.Event()
        self._recv_done = threading.Event()
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._recv_thread: Optional[threading.Thread] = None

    @property
    def token(self) -> str:
        """Identifies this lock acquisition, for audit/logging purposes."""
        with self._mu:
            return self._token

    @property
    def expires_at(self) -> Optional[datetime]:
        """The lock's current expiry, updated as heartbeats are acknowledged."""
        with self._mu:
            return self._expires_at

    def release(self) -> None:
        """Closes the lock stream, releasing the lock for the next waiting
        replica. Safe to call more than once; idempotent.
        """
        with self._mu:
            if self._released:
                return
            self._released = True

        self._heartbeat_stop.set()
        try:
            self._stream.close_send()
        finally:
            self._recv_done.wait()

    def _report_lost(self, err: BaseException) -> None:
        with self._mu:
            if self._released or self.lost_error is not None:
                return
            self.lost_error = err
        self.lost_event.set()

    def __enter__(self) -> "Lock":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()


def acquire_lock(client, namespace: str, service: str, ttl_seconds: float) -> Lock:
    """Blocks until this replica acquires signet's restart lock for
    ``namespace``/``service``, queueing behind any current holder.

    ``ttl_seconds`` must be > 0 and must cover the full time between
    acquiring the lock and calling ``lock.release()`` — signet has no
    server-side default. Heartbeats are sent automatically at
    ``ttl_seconds / 4`` (signet's documented convention: 4 consecutive
    missed heartbeats exhaust the TTL) until ``release()`` is called or the
    lock is lost (see ``Lock.lost_event``).

    Raises:
        ValueError: if ``ttl_seconds <= 0`` — raised before any stream is
            opened.
        SignetError: if the stream fails to open, or fails/closes before
            the lock is acquired.
    """
    if ttl_seconds <= 0:
        raise ValueError(f"signet: ttl_seconds must be > 0, got {ttl_seconds!r}")

    try:
        stream = _GrpcLockStream(client)
    except Exception as e:
        raise SignetError(f"signet: open AcquireRestartLock stream: {e}") from e

    return _acquire_lock_on_stream(stream, namespace, service, ttl_seconds)


def _acquire_lock_on_stream(
    stream: LockStream, namespace: str, service: str, ttl_seconds: float
) -> Lock:
    ttl_seconds_int = int(ttl_seconds)
    if ttl_seconds_int <= 0:
        ttl_seconds_int = 1

    request = pb.AcquireRestartLockRequest(
        namespace=namespace, service=service, ttl_seconds=ttl_seconds_int
    )
    try:
        stream.send(request)
    except Exception as e:
        raise SignetError(
            f"signet: send initial AcquireRestartLock request: {e}"
        ) from e

    lock = Lock(stream)
    acquired: "queue.Queue[Optional[BaseException]]" = queue.Queue(maxsize=1)

    recv_thread = threading.Thread(
        target=_recv_loop,
        args=(stream, lock, acquired),
        daemon=True,
        name="signet-lock-recv",
    )
    lock._recv_thread = recv_thread
    recv_thread.start()

    err = acquired.get()
    if err is not None:
        raise err

    heartbeat_thread = threading.Thread(
        target=_heartbeat_loop,
        args=(stream, lock, ttl_seconds_int),
        daemon=True,
        name="signet-lock-heartbeat",
    )
    lock._heartbeat_thread = heartbeat_thread
    heartbeat_thread.start()

    return lock


def _recv_loop(
    stream: LockStream, lock: Lock, acquired: "queue.Queue[Optional[BaseException]]"
) -> None:
    """Owns ``recv()`` for the stream's entire lifetime: it delivers the
    first ACQUIRED (or a fatal error before it) via ``acquired``, then keeps
    reading TTL_EXTENDED acks (updating expires_at) until the stream errors
    or closes, at which point it reports loss via ``lock._report_lost``
    (unless ``release()`` already initiated the close).
    """
    got_acquired = False
    try:
        while True:
            try:
                resp = stream.recv()
            except Exception as e:
                if not got_acquired:
                    err = SignetError(
                        f"signet: AcquireRestartLock stream failed before lock "
                        f"was acquired: {e}"
                    )
                    err.__cause__ = e
                    acquired.put(err)
                else:
                    lost = LockLostError(
                        f"signet: AcquireRestartLock stream ended unexpectedly "
                        f"while lock was held: {e}"
                    )
                    lost.__cause__ = e
                    lock._report_lost(lost)
                return

            message_type = resp.message_type
            if message_type == pb.AcquireRestartLockResponse.MESSAGE_TYPE_ACQUIRED:
                with lock._mu:
                    lock._token = resp.token
                    if resp.HasField("expires_at"):
                        lock._expires_at = resp.expires_at.ToDatetime(
                            tzinfo=timezone.utc
                        )
                if not got_acquired:
                    got_acquired = True
                    acquired.put(None)
            elif message_type == pb.AcquireRestartLockResponse.MESSAGE_TYPE_TTL_EXTENDED:
                with lock._mu:
                    if resp.HasField("expires_at"):
                        lock._expires_at = resp.expires_at.ToDatetime(
                            tzinfo=timezone.utc
                        )
            elif message_type == pb.AcquireRestartLockResponse.MESSAGE_TYPE_QUEUE_POSITION:
                # No state to update; callers who want position visibility
                # can drive acquire_lock's lower-level pieces themselves if
                # that becomes a real need.
                pass
    finally:
        lock._recv_done.set()


def _heartbeat_loop(stream: LockStream, lock: Lock, ttl_seconds_int: int) -> None:
    interval = ttl_seconds_int / 4.0
    if interval <= 0:
        interval = 1.0

    while not lock._heartbeat_stop.wait(interval):
        try:
            stream.send(pb.AcquireRestartLockRequest(heartbeat=True))
        except Exception as e:
            lost = LockLostError(f"signet: send heartbeat: {e}")
            lost.__cause__ = e
            lock._report_lost(lost)
            return


class _GrpcLockStream:
    """Adapts a ``SecretsServiceStub.AcquireRestartLock`` bidi-streaming call
    to the :class:`LockStream` protocol.

    grpc-python's bidi-streaming API takes a single request *iterator* up
    front rather than exposing an imperative ``send()``; we bridge that gap
    with a queue-backed generator, which is the standard pattern for
    interactive (as opposed to purely batch) bidi streaming in grpc-python.
    A background reader thread (started by the caller, see ``_recv_loop``)
    and this object's ``send()`` (called from the heartbeat thread) run
    concurrently — grpc-python's call objects support one reader thread and
    one writer thread concurrently.
    """

    _CLOSE = object()

    def __init__(self, client) -> None:
        self._send_queue: "queue.Queue[object]" = queue.Queue()
        self._call = client.AcquireRestartLock(self._request_iterator())

    def _request_iterator(self):
        while True:
            item = self._send_queue.get()
            if item is self._CLOSE:
                return
            yield item

    def send(self, request: pb.AcquireRestartLockRequest) -> None:
        self._send_queue.put(request)

    def recv(self) -> pb.AcquireRestartLockResponse:
        try:
            return next(self._call)
        except StopIteration:
            raise SignetError(
                "signet: AcquireRestartLock stream closed by server"
            ) from None

    def close_send(self) -> None:
        self._send_queue.put(self._CLOSE)


# =====================================================================
# WatchBundle
# =====================================================================


def _next_backoff(current: float) -> float:
    nxt = current * 2
    return _WATCH_BACKOFF_MAX if nxt > _WATCH_BACKOFF_MAX else nxt


class _StreamHolder:
    """Tracks the currently-open watch stream so ``Watch.close()`` can
    cancel an in-flight (blocking) ``recv()`` promptly instead of waiting
    for the next server message or reconnect-backoff tick.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stream: Optional[object] = None

    def set(self, stream: object) -> None:
        with self._lock:
            self._stream = stream

    def cancel(self) -> None:
        with self._lock:
            stream = self._stream
        cancel = getattr(stream, "cancel", None)
        if cancel is not None:
            cancel()


def _watch_loop(
    open_stream: Callable[[], WatchStream],
    changes: "queue.Queue[bool]",
    stop_event: threading.Event,
) -> None:
    """Watches for bundle-change notifications, reconnecting with
    exponential backoff (1s, doubling, capped at 30s, reset to 1s on any
    successful receive) if the stream breaks. Rapid successive changes are
    coalesced: ``changes`` only ever signals "at least one change happened
    since you last drained it," never a count.
    """
    backoff = _WATCH_BACKOFF_MIN
    while not stop_event.is_set():
        try:
            stream = open_stream()
        except Exception:
            if stop_event.wait(backoff):
                return
            backoff = _next_backoff(backoff)
            continue

        while True:
            try:
                resp = stream.recv()
            except Exception:
                break
            backoff = _WATCH_BACKOFF_MIN
            if resp.event_type == pb.WatchServiceBundleResponse.EVENT_TYPE_CHANGED:
                try:
                    changes.put_nowait(True)
                except queue.Full:
                    # Already a pending unread change signal; coalesce.
                    pass
            if stop_event.is_set():
                return

        if stop_event.is_set():
            return
        if stop_event.wait(backoff):
            return
        backoff = _next_backoff(backoff)


class _GrpcWatchStream:
    """Adapts a ``SecretsServiceStub.WatchServiceBundle`` server-streaming
    call to the :class:`WatchStream` protocol.
    """

    def __init__(self, call) -> None:
        self._call = call

    def recv(self) -> pb.WatchServiceBundleResponse:
        try:
            return next(self._call)
        except StopIteration:
            raise SignetError(
                "signet: WatchServiceBundle stream closed by server"
            ) from None

    def cancel(self) -> None:
        self._call.cancel()


class Watch:
    """Handle returned by :func:`watch_bundle`. Coalesces rapid successive
    changes: :meth:`wait_for_change` reports "at least one change happened,"
    never a count.
    """

    def __init__(
        self, open_stream: Callable[[], WatchStream], holder: Optional[_StreamHolder] = None
    ) -> None:
        self._changes: "queue.Queue[bool]" = queue.Queue(maxsize=1)
        self._stop = threading.Event()
        self._holder = holder
        self._thread = threading.Thread(
            target=_watch_loop,
            args=(open_stream, self._changes, self._stop),
            daemon=True,
            name="signet-watch",
        )
        self._thread.start()

    def wait_for_change(self, timeout: Optional[float] = None) -> bool:
        """Blocks until a change notification is available, ``timeout``
        seconds elapse, or the watch is closed. Returns True if a change was
        observed, False on timeout.
        """
        try:
            self._changes.get(timeout=timeout)
            return True
        except queue.Empty:
            return False

    def close(self, timeout: Optional[float] = None) -> None:
        """Stops the background watch loop. Safe to call more than once."""
        self._stop.set()
        if self._holder is not None:
            self._holder.cancel()
        self._thread.join(timeout=timeout)

    def __enter__(self) -> "Watch":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def watch_bundle(client, namespace: str, service: str) -> Watch:
    """Watches for signet bundle-change notifications for
    ``namespace``/``service``, reconnecting with exponential backoff if the
    stream breaks. See :class:`Watch`.
    """
    holder = _StreamHolder()

    def open_stream() -> WatchStream:
        call = client.WatchServiceBundle(
            pb.WatchServiceBundleRequest(namespace=namespace, service=service)
        )
        stream = _GrpcWatchStream(call)
        holder.set(stream)
        return stream

    return Watch(open_stream, holder=holder)


# =====================================================================
# WaitForRestart
# =====================================================================


def wait_for_restart(
    client,
    namespace: str,
    service: str,
    ttl_seconds: float,
    debounce_seconds: float = 0.0,
) -> Lock:
    """Convenience combining :func:`watch_bundle` and :func:`acquire_lock`:
    waits for the next bundle change (debounced by ``debounce_seconds`` — 0
    means act on the first event immediately), then acquires the restart
    lock, returning once held.

    Does **not** fetch the updated bundle: since this call doesn't spawn a
    replacement process, the next process instance fetches it fresh during
    its own normal startup. The caller — never this library — decides when
    to actually terminate the process.

    Typical caller shape::

        lock = wait_for_restart(client, ns, svc, ttl_seconds=30, debounce_seconds=10)
        # ... graceful shutdown: drain in-flight requests, close resources ...
        lock.release()
        sys.exit(0)
    """
    watch = watch_bundle(client, namespace, service)
    try:
        watch.wait_for_change()

        if debounce_seconds > 0:
            while watch.wait_for_change(timeout=debounce_seconds):
                pass  # a new change arrived inside the debounce window; keep waiting

        return acquire_lock(client, namespace, service, ttl_seconds)
    finally:
        watch.close()
