"""Connection helper for signet's workload-facing SecretsService, authenticated
via SPIFFE mTLS.

Requires the optional ``spiffe`` extra: ``pip install signet-client[workload]``.
That package (PyPI: ``spiffe``, https://github.com/HewlettPackard/py-spiffe)
is the actively-maintained Python SPIFFE Workload API client — confirmed via
its PyPI release history and GitHub activity while building this module (see
python/README.md's "SPIFFE support" section for the full writeup, including
a real gap: grpc-python has no public hook for inspecting the server's
presented SPIFFE ID after the TLS handshake, so this module cannot fully
replicate the Go client's ``tlsconfig.AuthorizeMemberOf`` semantics — see
below and the README for what is and isn't covered).
"""

from __future__ import annotations

from typing import Optional, Tuple

import grpc

from signet.v1 import secrets_pb2_grpc

from .errors import SignetError

__all__ = ["dial_workload", "secrets_client"]


def secrets_client(channel: grpc.Channel) -> secrets_pb2_grpc.SecretsServiceStub:
    """Returns a SecretsService client bound to ``channel``."""
    return secrets_pb2_grpc.SecretsServiceStub(channel)


def dial_workload(
    addr: str,
    socket_path: str,
    trust_domain: str,
    timeout: Optional[float] = None,
):
    """Opens a gRPC channel to signet's workload listener, authenticating via
    SPIFFE mTLS.

    ``socket_path`` is the SPIFFE Workload API socket (e.g.
    ``unix:///run/spire/sockets/agent.sock``); ``trust_domain`` must match
    the trust domain of the target signet instance.

    Returns a ``(channel, source)`` pair. ``source`` is the underlying
    ``spiffe.X509Source``, which owns a background connection to the
    Workload API and must be closed alongside the channel:

        channel, source = dial_workload(addr, socket_path, trust_domain)
        try:
            client = secrets_client(channel)
            ...
        finally:
            channel.close()
            source.close()

    Authorization note: the returned channel only trusts certificate chains
    that validate against ``trust_domain``'s own X.509 CA bundle (fetched
    from the Workload API), which is the primary SPIFFE mTLS authorization
    boundary. Unlike the Go client's ``tlsconfig.AuthorizeMemberOf``, this
    does **not** perform an additional post-handshake check that the
    server's leaf certificate SPIFFE ID SAN is itself a member of
    ``trust_domain`` — grpc-python's public ``grpc.secure_channel`` /
    ``grpc.ssl_channel_credentials`` API has no hook to inspect the peer
    certificate after the handshake the way Go's ``grpc-go`` transport
    credentials do. In the common (non-federated) case this distinction is
    largely academic, since a trust domain's own CA only ever signs SVIDs
    for that trust domain; it matters mainly under federation, where a
    single CA might be trusted by multiple trust domains. See
    python/README.md for more detail.

    Raises:
        SignetError: if the optional ``spiffe`` package isn't installed, the
            Workload API can't be reached, ``trust_domain`` is malformed, no
            X.509 bundle is available for it, or the channel fails to dial.
    """
    try:
        from spiffe import TrustDomain, X509Source
    except ImportError as e:
        raise SignetError(
            "signet: dial_workload requires the optional 'spiffe' package; "
            "install with `pip install signet-client[workload]` (see "
            "python/README.md's SPIFFE section)"
        ) from e

    from cryptography.hazmat.primitives import serialization

    try:
        td = TrustDomain(trust_domain)
    except Exception as e:
        raise SignetError(
            f"signet: invalid trust domain {trust_domain!r}: {e}"
        ) from e

    try:
        source = X509Source(socket_path=socket_path, timeout_in_seconds=timeout)
    except Exception as e:
        raise SignetError(
            f"signet: connect to SPIFFE workload API at {socket_path!r}: {e}"
        ) from e

    try:
        context = source.get_x509_context()
        svid = context.default_svid
        bundle = context.x509_bundle_set.get_bundle_for_trust_domain(td)
        if bundle is None:
            raise SignetError(
                f"signet: no X.509 bundle available for trust domain "
                f"{trust_domain!r} (is the Workload API federated with it?)"
            )

        cert_chain_pem = b"".join(
            cert.public_bytes(serialization.Encoding.PEM) for cert in svid.cert_chain
        )
        private_key_pem = svid.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        root_certificates_pem = b"".join(
            cert.public_bytes(serialization.Encoding.PEM)
            for cert in bundle.x509_authorities
        )

        creds = grpc.ssl_channel_credentials(
            root_certificates=root_certificates_pem,
            private_key=private_key_pem,
            certificate_chain=cert_chain_pem,
        )
        channel = grpc.secure_channel(addr, creds)
    except SignetError:
        source.close()
        raise
    except Exception as e:
        source.close()
        raise SignetError(f"signet: dial {addr}: {e}") from e

    return channel, source
