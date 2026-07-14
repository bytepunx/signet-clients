#!/usr/bin/env python3
"""TEST-ONLY smoke-test fixture for the signet Python client.

Deployed as a single minimal container into a real Kubernetes cluster
running signet + SPIRE (see bytepunx/signet-smoke-test), to prove this
client library actually works end-to-end against a live signet instance —
not just the hand-written fakes the rest of this repo's test suite uses.

Configuration comes entirely from the environment (this runs as a
Kubernetes container; there is no interactive CLI):

    SIGNET_ADDR               signet workload gRPC address, e.g.
                               signet.signet.svc.cluster.local:8443
    SIGNET_TRUST_DOMAIN       SPIFFE trust domain
    SPIFFE_WORKLOAD_SOCKET    SPIFFE Workload API socket, as a unix:// URI,
                               e.g. unix:///run/spiffe.io/spire-agent.sock
    SIGNET_NAMESPACE          signet namespace to fetch (populated via the
                               Kubernetes Downward API in the Deployment
                               manifest)
    SIGNET_SERVICE            signet service to fetch
    RESTART_LOCK_TTL_SECONDS  optional, default 30
    RESTART_DEBOUNCE_SECONDS  optional, default 5

Sequence:
    1. Print the test-only banner (unconditionally, first thing).
    2. dial_workload to connect over SPIFFE mTLS.
    3. GetServiceBundle and print it as a single ECHO_BUNDLE: <json> line,
       with secrets base64-decoded, for log-based verification.
    4. Block in wait_for_restart (steady state: this blocks indefinitely
       until something changes).
    5. On return, print a single ECHO_RESTART: ... line describing the
       acquired lock, release it, and exit 0 — Kubernetes restarts the pod
       (restartPolicy: Always), and the new instance repeats from step 1
       against whatever changed. That round-trip is what this fixture
       exists to prove.

Requires the optional `spiffe` extra: pip install signet-client[workload]
"""

from __future__ import annotations

import base64
import json
import logging
import os
import signal
import sys
from typing import NoReturn

from google.protobuf import json_format

from signet.v1 import secrets_pb2 as pb
from signet_client import dial_workload, secrets_client, wait_for_restart

BANNER = (
    "TEST-ONLY BUILD — DO NOT RUN IN PRODUCTION. "
    "This program prints retrieved secrets to stdout."
)

DEFAULT_LOCK_TTL_SECONDS = 30.0
DEFAULT_DEBOUNCE_SECONDS = 5.0

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("echo")


class _Interrupted(Exception):
    """Raised from a signal handler to unwind out of whatever blocking call
    (dial_workload, GetServiceBundle, wait_for_restart) is in progress.
    """

    def __init__(self, signum: int) -> None:
        super().__init__(signum)
        self.signum = signum


def _on_signal(signum: int, frame) -> None:  # noqa: ANN001 - stdlib signature
    raise _Interrupted(signum)


def _require_env(name: str) -> str:
    """Returns the value of the required environment variable ``name``, or
    exits with a clear, specific error naming it if missing or empty.
    """
    value = os.environ.get(name)
    if not value:
        _fail(f"missing required environment variable: {name}")
    return value


def _optional_float_env(name: str, default: float) -> float:
    """Returns the environment variable ``name`` parsed as a float, or
    ``default`` if it's unset, empty, or fails to parse.
    """
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        log.warning("ignoring invalid %s=%r; using default %s", name, raw, default)
        return default


def _fail(message: str) -> NoReturn:
    log.error(message)
    sys.exit(1)


def _iso(dt) -> str:  # noqa: ANN001 - datetime | None
    return dt.isoformat() if dt is not None else "unknown"


def _bundle_to_json(resp: pb.GetServiceBundleResponse) -> str:
    """Converts a GetServiceBundleResponse into the ECHO_BUNDLE JSON payload:
    config fields at the top level (as signet returns them), plus
    config_version, with the reserved "secrets" sub-map base64-decoded so
    verification can read plaintext values straight off the log line.
    """
    fields = json_format.MessageToDict(resp.bundle)
    secrets_b64 = fields.pop("secrets", {}) or {}
    secrets = {
        name: base64.b64decode(value).decode("utf-8")
        for name, value in secrets_b64.items()
    }
    fields["config_version"] = resp.config_version
    fields["secrets"] = secrets
    return json.dumps(fields, sort_keys=True)


def main() -> int:
    # 1. Banner: unconditionally, before anything else.
    print(BANNER, flush=True)

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    addr = _require_env("SIGNET_ADDR")
    trust_domain = _require_env("SIGNET_TRUST_DOMAIN")
    socket_path = _require_env("SPIFFE_WORKLOAD_SOCKET")
    namespace = _require_env("SIGNET_NAMESPACE")
    service = _require_env("SIGNET_SERVICE")
    ttl_seconds = _optional_float_env("RESTART_LOCK_TTL_SECONDS", DEFAULT_LOCK_TTL_SECONDS)
    debounce_seconds = _optional_float_env(
        "RESTART_DEBOUNCE_SECONDS", DEFAULT_DEBOUNCE_SECONDS
    )

    channel = None
    source = None
    lock = None
    try:
        # 2. Connect over SPIFFE mTLS.
        channel, source = dial_workload(addr, socket_path, trust_domain, timeout=10)
        client = secrets_client(channel)

        # 3. Fetch and print the bundle for log-based verification.
        resp = client.GetServiceBundle(
            pb.GetServiceBundleRequest(namespace=namespace, service=service),
            timeout=10,
        )
        print(f"ECHO_BUNDLE: {_bundle_to_json(resp)}", flush=True)

        # 4. Block until signet reports a change AND this replica holds the
        # restart lock. Steady state: this blocks indefinitely.
        lock = wait_for_restart(
            client, namespace, service,
            ttl_seconds=ttl_seconds, debounce_seconds=debounce_seconds,
        )

        # 5. Report, release, and let Kubernetes restart the pod.
        print(f"ECHO_RESTART: token={lock.token} expires_at={_iso(lock.expires_at)}", flush=True)
        return 0
    except _Interrupted as e:
        log.info(
            "received signal %s, shutting down without restarting",
            signal.Signals(e.signum).name,
        )
        return 0
    finally:
        if lock is not None:
            try:
                lock.release()
            except Exception as e:  # noqa: BLE001 - best-effort on the way out
                log.warning("lock release failed (it will still expire via TTL): %s", e)
        if channel is not None:
            channel.close()
        if source is not None:
            source.close()


if __name__ == "__main__":
    sys.exit(main())
