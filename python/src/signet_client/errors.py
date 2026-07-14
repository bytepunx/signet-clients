"""Exceptions raised by signet_client.

All errors raised by this library that stem from a connectivity/protocol
failure (as opposed to a plain bad-argument ``ValueError``) are instances of
:class:`SignetError`, so callers can catch a single type. Every
``SignetError`` is raised with ``raise ... from e`` when it wraps an
underlying exception, so the original traceback/cause is never lost — just
given a clear, specific, actionable message in front of it.
"""

from __future__ import annotations

__all__ = ["SignetError", "LockLostError"]


class SignetError(Exception):
    """Base class for signet_client errors.

    Raised for connection/dial failures, malformed server input, and
    protocol-level problems (e.g. a lock stream failing before ACQUIRED).
    Argument-validation errors (e.g. ``ttl_seconds <= 0``, an empty admin
    token) are raised as plain :class:`ValueError` instead, per Python
    convention.
    """


class LockLostError(SignetError):
    """Raised (and stored on :attr:`Lock.lost_error`) when a held restart
    lock is lost unexpectedly — the stream errored or the server closed it
    without a matching :meth:`Lock.release` call.

    Treat this as "another replica may now acquire the lock and restart
    concurrently": there is nothing to undo, only to log.
    """
