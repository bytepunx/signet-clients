"""signet_client — Python client library for signet.

Two connection modes mirror the two listeners signet exposes:

- :func:`dial_workload` connects to the workload-facing ``SecretsService``
  using SPIFFE mTLS (requires the optional ``spiffe`` extra — see
  :mod:`signet_client.workload`).
- :func:`dial_admin` connects to the operator-facing
  ``AdminService``/``GitOpsService`` using a bearer token over TLS (or
  plaintext for loopback addresses).

:func:`watch_bundle`, :func:`acquire_lock`, and :func:`wait_for_restart`
implement signet's coordinated-restart protocol against any
``SecretsServiceStub`` (i.e. against a channel you dial yourself, or one
returned by :func:`dial_workload`) — see python/README.md's "Coordinated
restarts" section.
"""

from .admin import admin_client, dial_admin, gitops_client, read_ca_file
from .errors import LockLostError, SignetError
from .restart import Lock, Watch, acquire_lock, wait_for_restart, watch_bundle
from .workload import dial_workload, secrets_client

__all__ = [
    "SignetError",
    "LockLostError",
    "dial_admin",
    "admin_client",
    "gitops_client",
    "read_ca_file",
    "dial_workload",
    "secrets_client",
    "Lock",
    "Watch",
    "acquire_lock",
    "watch_bundle",
    "wait_for_restart",
]
