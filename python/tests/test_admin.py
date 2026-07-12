"""Tests for signet_client.admin's DialAdmin connection helper.

Ported from go/client_test.go, plus a few Python-specific additions (the
bearer-token interceptor's metadata injection, and a valid-CA-PEM happy
path). No live network connection or signet instance is used anywhere —
dial_admin builds a channel object but nothing here actually connects it.
"""

from __future__ import annotations

import datetime

import grpc
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from signet_client.admin import (
    _admin_transport_credentials,
    _BearerTokenInterceptor,
    _split_host,
    dial_admin,
    is_loopback_host,
    read_ca_file,
)
from signet_client.errors import SignetError


def _self_signed_ca_pem() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.mark.parametrize(
    "host,want",
    [
        ("localhost", True),
        ("127.0.0.1", True),
        ("::1", True),
        ("10.0.0.5", False),
        ("signet.internal", False),
    ],
)
def test_is_loopback_host(host, want):
    assert is_loopback_host(host) == want


@pytest.mark.parametrize(
    "addr,host",
    [
        ("localhost:8444", "localhost"),
        ("signet.internal:8444", "signet.internal"),
        ("127.0.0.1:8444", "127.0.0.1"),
        ("[::1]:8444", "::1"),
        ("localhost", "localhost"),
    ],
)
def test_split_host(addr, host):
    assert _split_host(addr) == host


def test_admin_transport_creds_loopback_defaults_plaintext():
    _, require_tls = _admin_transport_credentials("localhost:8444", None, False)
    assert require_tls is False, "expected plaintext for loopback address without force_tls"


def test_admin_transport_creds_non_loopback_requires_tls():
    _, require_tls = _admin_transport_credentials("signet.internal:8444", None, False)
    assert require_tls is True, "expected TLS to be required for a non-loopback address"


def test_admin_transport_creds_force_tls_on_loopback():
    _, require_tls = _admin_transport_credentials("localhost:8444", None, True)
    assert require_tls is True, "expected TLS to be required when force_tls is set"


def test_admin_transport_creds_invalid_ca_pem():
    with pytest.raises(SignetError, match=r"no PEM certificates found"):
        _admin_transport_credentials("signet.internal:8444", b"not a cert", False)


def test_admin_transport_creds_invalid_ca_pem_malformed_block():
    # Has BEGIN/END markers (so it's not "no certificates found") but the
    # base64 content between them is garbage.
    bad = b"-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n"
    with pytest.raises(SignetError, match=r"invalid CA PEM"):
        _admin_transport_credentials("signet.internal:8444", bad, False)


def test_admin_transport_creds_valid_ca_pem_succeeds():
    creds, require_tls = _admin_transport_credentials(
        "signet.internal:8444", _self_signed_ca_pem(), False
    )
    assert require_tls is True
    assert creds is not None


def test_dial_admin_rejects_empty_token():
    with pytest.raises(ValueError, match=r"token must not be empty"):
        dial_admin("localhost:8444", "  ", None, False)


def test_dial_admin_rejects_missing_token():
    with pytest.raises(ValueError, match=r"token must not be empty"):
        dial_admin("localhost:8444", "", None, False)


def test_dial_admin_plaintext_loopback_returns_channel():
    channel = dial_admin("localhost:0", "tok", None, False)
    try:
        assert isinstance(channel, grpc.Channel)
    finally:
        channel.close()


def test_dial_admin_tls_non_loopback_returns_channel():
    channel = dial_admin("signet.internal:8444", "tok", _self_signed_ca_pem(), False)
    try:
        assert isinstance(channel, grpc.Channel)
    finally:
        channel.close()


def test_dial_admin_invalid_ca_pem_raises_clear_error():
    with pytest.raises(SignetError, match=r"invalid CA PEM|no PEM certificates"):
        dial_admin("signet.internal:8444", "tok", b"garbage", False)


def test_read_ca_file(tmp_path):
    pem = _self_signed_ca_pem()
    path = tmp_path / "ca.pem"
    path.write_bytes(pem)
    assert read_ca_file(str(path)) == pem


def test_bearer_token_interceptor_injects_authorization_metadata():
    interceptor = _BearerTokenInterceptor("secret-token")
    captured = {}

    def continuation(call_details, request):
        captured["details"] = call_details
        captured["request"] = request
        return "response"

    class _Details:
        method = "/signet.admin.v1.AdminService/Status"
        timeout = None
        metadata = None
        credentials = None
        wait_for_ready = None
        compression = None

    result = interceptor.intercept_unary_unary(continuation, _Details(), "req")

    assert result == "response"
    assert captured["request"] == "req"
    assert ("authorization", "Bearer secret-token") in captured["details"].metadata


def test_bearer_token_interceptor_preserves_existing_metadata():
    interceptor = _BearerTokenInterceptor("tok")
    captured = {}

    def continuation(call_details, request):
        captured["details"] = call_details
        return None

    class _Details:
        method = "/x/Y"
        timeout = None
        metadata = [("x-request-id", "abc")]
        credentials = None
        wait_for_ready = None
        compression = None

    interceptor.intercept_unary_unary(continuation, _Details(), "req")

    metadata = captured["details"].metadata
    assert ("x-request-id", "abc") in metadata
    assert ("authorization", "Bearer tok") in metadata
