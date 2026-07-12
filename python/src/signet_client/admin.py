"""Connection helper for signet's operator-facing AdminService/GitOpsService.

Mirrors the Go client's ``DialAdmin``: bearer-token auth over TLS, with
plaintext allowed only for loopback addresses (the documented
``kubectl port-forward`` workflow), matching signet's own ``signet`` CLI.
This module has no SPIFFE dependency.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional, Sequence, Tuple

import grpc
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from admin.v1 import admin_pb2_grpc

from .errors import SignetError

__all__ = [
    "dial_admin",
    "admin_client",
    "gitops_client",
    "read_ca_file",
]

_HOST_PORT_RE = re.compile(r"^\[(?P<host>[^\]]+)\](:\d+)?$")
_PEM_CERT_BLOCK_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL
)


def dial_admin(
    addr: str,
    token: str,
    ca_pem: Optional[bytes] = None,
    force_tls: bool = False,
    **channel_kwargs,
) -> grpc.Channel:
    """Opens a gRPC channel to signet's admin listener, injecting ``token``
    as a bearer credential on every outgoing RPC.

    Loopback addresses (``localhost``, ``127.0.0.1``, ``::1``, ...) use
    plaintext by default; every other address is upgraded to TLS
    automatically, using the system trust store unless ``ca_pem`` is given.
    ``force_tls`` requests TLS even for a loopback address.

    Raises:
        ValueError: if ``token`` is empty or whitespace-only.
        SignetError: if ``ca_pem`` is provided but contains no parseable PEM
            certificates.
    """
    if not token or not token.strip():
        raise ValueError("signet: token must not be empty")

    creds, require_tls = _admin_transport_credentials(addr, ca_pem, force_tls)
    interceptor = _BearerTokenInterceptor(token.strip())

    if require_tls:
        channel = grpc.secure_channel(addr, creds, **channel_kwargs)
    else:
        channel = grpc.insecure_channel(addr, **channel_kwargs)

    return grpc.intercept_channel(channel, interceptor)


def admin_client(channel: grpc.Channel) -> admin_pb2_grpc.AdminServiceStub:
    """Returns an AdminService client bound to ``channel``."""
    return admin_pb2_grpc.AdminServiceStub(channel)


def gitops_client(channel: grpc.Channel) -> admin_pb2_grpc.GitOpsServiceStub:
    """Returns a GitOpsService client bound to ``channel``."""
    return admin_pb2_grpc.GitOpsServiceStub(channel)


def read_ca_file(path: str) -> bytes:
    """Reads a PEM CA bundle from ``path`` for use with :func:`dial_admin`."""
    with open(path, "rb") as f:
        return f.read()


def _admin_transport_credentials(
    addr: str, ca_pem: Optional[bytes], force_tls: bool
) -> Tuple[Optional[grpc.ChannelCredentials], bool]:
    host = _split_host(addr)
    use_tls = force_tls or bool(ca_pem) or not is_loopback_host(host)

    if not use_tls:
        return None, False

    root_certificates = None
    if ca_pem:
        _validate_ca_pem(ca_pem)
        root_certificates = ca_pem

    return grpc.ssl_channel_credentials(root_certificates=root_certificates), True


def _validate_ca_pem(ca_pem: bytes) -> None:
    """Parses every PEM certificate block in ``ca_pem``, raising a clear
    SignetError instead of letting a malformed bundle surface as an opaque
    TLS handshake failure later. Mirrors Go's
    ``x509.NewCertPool().AppendCertsFromPEM()`` validation.
    """
    blocks = _PEM_CERT_BLOCK_RE.findall(ca_pem)
    if not blocks:
        raise SignetError(
            "signet: no PEM certificates found in provided CA bundle"
        )
    for i, block in enumerate(blocks):
        try:
            x509.load_pem_x509_certificate(block, default_backend())
        except Exception as e:
            raise SignetError(
                f"signet: invalid CA PEM: failed to parse certificate #{i + 1} "
                f"in provided CA bundle: {e}"
            ) from e


def is_loopback_host(host: str) -> bool:
    """True if ``host`` resolves to a loopback address without a DNS
    lookup — i.e. it's literally ``localhost`` or a loopback IP literal.
    """
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback


def _split_host(addr: str) -> str:
    """Splits ``host:port`` (or ``[ipv6]:port``) down to just the host,
    mirroring Go's ``net.SplitHostPort`` fallback: if ``addr`` doesn't parse
    as host:port, treat the whole string as the host.
    """
    m = _HOST_PORT_RE.match(addr)
    if m:
        return m.group("host")
    head, sep, tail = addr.rpartition(":")
    if sep and tail.isdigit():
        return head
    return addr


class _BearerTokenInterceptor(
    grpc.UnaryUnaryClientInterceptor,
    grpc.UnaryStreamClientInterceptor,
    grpc.StreamUnaryClientInterceptor,
    grpc.StreamStreamClientInterceptor,
):
    """Injects ``Authorization: Bearer <token>`` into every outgoing RPC.

    Implemented as a client interceptor rather than ``grpc.CallCredentials``
    because grpc-python's call-credentials machinery refuses to attach to a
    plaintext (insecure) channel — there is no public equivalent of Go's
    ``PerRPCCredentials.RequireTransportSecurity() == false`` escape hatch,
    which is what lets the Go client send bearer tokens over the documented
    plaintext loopback (``kubectl port-forward``) path. An interceptor works
    uniformly for both the plaintext and TLS cases.
    """

    def __init__(self, token: str) -> None:
        self._metadata: Sequence[Tuple[str, str]] = (("authorization", f"Bearer {token}"),)

    def _add_metadata(self, client_call_details):
        metadata = list(client_call_details.metadata or [])
        metadata.extend(self._metadata)
        return _ClientCallDetails(
            method=client_call_details.method,
            timeout=client_call_details.timeout,
            metadata=metadata,
            credentials=client_call_details.credentials,
            wait_for_ready=getattr(client_call_details, "wait_for_ready", None),
            compression=getattr(client_call_details, "compression", None),
        )

    def intercept_unary_unary(self, continuation, client_call_details, request):
        return continuation(self._add_metadata(client_call_details), request)

    def intercept_unary_stream(self, continuation, client_call_details, request):
        return continuation(self._add_metadata(client_call_details), request)

    def intercept_stream_unary(self, continuation, client_call_details, request_iterator):
        return continuation(self._add_metadata(client_call_details), request_iterator)

    def intercept_stream_stream(self, continuation, client_call_details, request_iterator):
        return continuation(self._add_metadata(client_call_details), request_iterator)


class _ClientCallDetails(grpc.ClientCallDetails):
    """Minimal concrete ``ClientCallDetails`` — the ``grpc`` module only
    provides the (attribute-only) interface, not an implementation.
    """

    def __init__(self, method, timeout, metadata, credentials, wait_for_ready, compression):
        self.method = method
        self.timeout = timeout
        self.metadata = metadata
        self.credentials = credentials
        self.wait_for_ready = wait_for_ready
        self.compression = compression
