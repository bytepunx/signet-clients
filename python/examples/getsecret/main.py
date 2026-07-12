#!/usr/bin/env python3
"""Minimal example of using the signet Python client to fetch a secret over
SPIFFE mTLS.

Requires the optional `spiffe` extra: pip install signet-client[workload]

Usage:
    python examples/getsecret/main.py \
        --addr localhost:8443 \
        --socket unix:///run/spire/sockets/agent.sock \
        --trust-domain example.org \
        --namespace default --service example --name api-key
"""

from __future__ import annotations

import argparse
import sys

from signet.v1 import secrets_pb2 as pb
from signet_client import dial_workload, secrets_client


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--addr", default="localhost:8443", help="signet workload gRPC address")
    parser.add_argument(
        "--socket",
        default="unix:///run/spire/sockets/agent.sock",
        help="SPIFFE Workload API socket",
    )
    parser.add_argument("--trust-domain", default="example.org", help="expected SPIFFE trust domain")
    parser.add_argument("--namespace", default="default", help="secret namespace")
    parser.add_argument("--service", default="example", help="secret service")
    parser.add_argument("--name", default="api-key", help="secret name")
    args = parser.parse_args()

    channel, source = dial_workload(args.addr, args.socket, args.trust_domain, timeout=10)
    try:
        client = secrets_client(channel)
        resp = client.GetSecret(
            pb.GetSecretRequest(
                namespace=args.namespace, service=args.service, name=args.name
            ),
            timeout=10,
        )
        print(f"version={resp.version} value={resp.value!r}")
    finally:
        channel.close()
        source.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
