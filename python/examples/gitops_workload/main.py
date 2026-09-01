#!/usr/bin/env python3
"""Example of calling GitOpsService over a workload's own SPIFFE mTLS
identity instead of an admin bearer token.

Requires the optional `spiffe` extra: pip install signet-client[workload]

dial_workload returns a plain grpc.Channel — the same one secrets_client
binds to in examples/getsecret — so gitops_client(channel) works exactly the
same way. This is the self-service path signet's server already supports
for SyncBundle, PatchServiceConfig, and GetSOPSPublicKey
(bytepunx/signet#23, #38, #78): a workload can push its own bundle, patch
its own config, or fetch signet's active SOPS public key using nothing but
its own workload identity, with no admin token in the picture at all.
Cross-namespace/service writes still require an explicit CreatePolicy grant
from an operator — see the design doc's "Self-service workload pushes"
section.

This example calls GetSOPSPublicKey specifically because it needs no setup
(no bundle to build, no JSON Patch to construct) — SyncBundle and
PatchServiceConfig are reachable the identical way, just call a different
method on the same client.

Usage:
    python examples/gitops_workload/main.py \
        --addr localhost:8443 \
        --socket unix:///run/spire/sockets/agent.sock \
        --trust-domain example.org
"""

from __future__ import annotations

import argparse
import sys

from admin.v1 import admin_pb2 as pb
from signet_client import dial_workload, gitops_client


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--addr", default="localhost:8443", help="signet workload gRPC address")
    parser.add_argument(
        "--socket",
        default="unix:///run/spire/sockets/agent.sock",
        help="SPIFFE Workload API socket",
    )
    parser.add_argument("--trust-domain", default="example.org", help="expected SPIFFE trust domain")
    args = parser.parse_args()

    channel, source = dial_workload(args.addr, args.socket, args.trust_domain, timeout=10)
    try:
        # gitops_client accepts any grpc.Channel, including the one
        # dial_workload built for the SecretsService client above — no
        # separate dial mode is needed.
        client = gitops_client(channel)
        resp = client.GetSOPSPublicKey(pb.GetSOPSPublicKeyRequest(), timeout=10)
        print(f"public_key={resp.public_key} fingerprint={resp.fingerprint} environment={resp.environment!r}")
    finally:
        channel.close()
        source.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
