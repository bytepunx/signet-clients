#!/usr/bin/env python3
"""Demonstrates the intended pattern for a service that pulls its own signet
configuration directly, in-memory, and coordinates a safe restart when that
configuration changes — without a process host and without ever writing
secrets to its environment.

The pattern:
  1. Fetch the bundle once at startup and configure the app in memory.
  2. Serve traffic normally.
  3. Block on wait_for_restart, which only returns once signet reports a
     change AND this replica has acquired the distributed restart lock —
     guaranteeing at most one replica restarts at a time fleet-wide.
  4. Do your own graceful shutdown (drain in-flight requests, close
     resources).
  5. Release the lock, then exit. Kubernetes starts a fresh process, which
     repeats from step 1 with the new configuration.

Requires the optional `spiffe` extra: pip install signet-client[workload]
"""

from __future__ import annotations

import argparse
import logging
import sys

from signet.v1 import secrets_pb2 as pb
from signet_client import dial_workload, secrets_client, wait_for_restart

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("restart-on-change")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--addr", default="localhost:8443", help="signet workload gRPC address")
    parser.add_argument(
        "--socket",
        default="unix:///run/spire/sockets/agent.sock",
        help="SPIFFE Workload API socket",
    )
    parser.add_argument("--trust-domain", default="example.org", help="expected SPIFFE trust domain")
    parser.add_argument("--namespace", default="default", help="bundle/lock namespace")
    parser.add_argument("--service", default="example", help="bundle/lock service")
    parser.add_argument(
        "--lock-ttl",
        type=float,
        default=30.0,
        help="restart lock TTL in seconds — must cover your graceful shutdown time",
    )
    parser.add_argument(
        "--debounce",
        type=float,
        default=10.0,
        help="seconds to wait after a change before acting, to absorb rapid successive edits",
    )
    args = parser.parse_args()

    channel, source = dial_workload(args.addr, args.socket, args.trust_domain, timeout=10)
    try:
        client = secrets_client(channel)

        # 1. Fetch once at startup; configure the app in memory. Never write
        # this to the environment or disk.
        bundle = client.GetServiceBundle(
            pb.GetServiceBundleRequest(namespace=args.namespace, service=args.service),
            timeout=10,
        )
        log.info("configured: config_version=%s", bundle.config_version)

        # 2. Serve traffic normally (omitted — this is a minimal example).

        # 3. Block until a change is reported and this replica holds the lock.
        try:
            lock = wait_for_restart(
                client, args.namespace, args.service, args.lock_ttl, args.debounce
            )
        except KeyboardInterrupt:
            log.info("shutting down: interrupted before any change arrived")
            return 0

        log.info("restart lock acquired: token=%s expires_at=%s", lock.token, lock.expires_at)

        # 4. Graceful shutdown: drain in-flight requests, close resources.
        # (omitted — this is a minimal example).

        # 5. Release the lock for the next waiting replica, then exit.
        # Kubernetes restarts the pod; the new process fetches the bundle
        # fresh.
        try:
            lock.release()
        except Exception as e:
            log.warning("lock release failed (it will still expire via TTL): %s", e)
    finally:
        channel.close()
        source.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
