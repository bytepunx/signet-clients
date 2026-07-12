"""Tests for signet_client.workload's dial_workload SPIFFE helper.

No live SPIRE agent / Workload API socket is used: the "spiffe" package's
X509Source is monkeypatched with a fake exposing the same shape (get_x509_context
-> context.default_svid / context.x509_bundle_set), built from a real
self-signed certificate (via `cryptography`) so the PEM-serialization code
path is exercised for real, just not the network fetch.
"""

from __future__ import annotations

import datetime
import sys

import grpc
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import spiffe as real_spiffe
from signet_client import workload as workload_mod
from signet_client.errors import SignetError


def _self_signed(cn: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


class _FakeSvid:
    def __init__(self, key, cert):
        self.private_key = key
        self.cert_chain = [cert]


class _FakeBundle:
    def __init__(self, cert, present=True):
        self._authorities = {cert} if present else set()
        self._present = present

    @property
    def x509_authorities(self):
        return self._authorities


class _FakeBundleSet:
    def __init__(self, bundle):
        self._bundle = bundle

    def get_bundle_for_trust_domain(self, td):
        # Mirrors spiffe.X509BundleSet.get_bundle_for_trust_domain: None if
        # no bundle is known for that trust domain (e.g. not federated).
        if not self._bundle._present:
            return None
        return self._bundle


class _FakeContext:
    def __init__(self, svid, bundle):
        self._svid = svid
        self._bundle_set = _FakeBundleSet(bundle)

    @property
    def default_svid(self):
        return self._svid

    @property
    def x509_bundle_set(self):
        return self._bundle_set


class _FakeX509Source:
    """Stands in for spiffe.X509Source: construction never touches a real
    Workload API socket in these tests.
    """

    instances = []

    def __init__(self, socket_path=None, timeout_in_seconds=None, bundle_present=True):
        self.socket_path = socket_path
        self.closed = False
        key, cert = _self_signed("workload")
        self._context = _FakeContext(
            _FakeSvid(key, cert), _FakeBundle(cert, present=bundle_present)
        )
        _FakeX509Source.instances.append(self)

    def get_x509_context(self):
        return self._context

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def _reset_fake_instances():
    _FakeX509Source.instances = []
    yield
    _FakeX509Source.instances = []


def test_dial_workload_missing_spiffe_package_raises_clear_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "spiffe", None)
    with pytest.raises(SignetError, match=r"requires the optional 'spiffe' package"):
        workload_mod.dial_workload(
            "signet.internal:8443", "unix:///tmp/agent.sock", "example.org"
        )


def test_dial_workload_invalid_trust_domain_raises_clear_error():
    with pytest.raises(SignetError, match=r"invalid trust domain"):
        workload_mod.dial_workload(
            "signet.internal:8443",
            "unix:///tmp/nonexistent.sock",
            "not a valid trust domain!!",
        )


def test_dial_workload_wraps_workload_api_connection_failure(monkeypatch):
    def _raise(*args, **kwargs):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(real_spiffe, "X509Source", _raise)

    with pytest.raises(SignetError, match=r"connect to SPIFFE workload API.*connection refused"):
        workload_mod.dial_workload(
            "signet.internal:8443", "unix:///tmp/agent.sock", "example.org"
        )


def test_dial_workload_succeeds_with_fake_source(monkeypatch):
    monkeypatch.setattr(real_spiffe, "X509Source", _FakeX509Source)

    channel, source = workload_mod.dial_workload(
        "signet.internal:8443", "unix:///tmp/agent.sock", "example.org"
    )
    try:
        assert isinstance(channel, grpc.Channel)
        assert source is _FakeX509Source.instances[0]
        assert source.socket_path == "unix:///tmp/agent.sock"
    finally:
        channel.close()
        source.close()

    assert source.closed is True


def test_dial_workload_missing_bundle_raises_clear_error_and_closes_source(monkeypatch):
    def _make_source_without_bundle(socket_path=None, timeout_in_seconds=None):
        return _FakeX509Source(
            socket_path=socket_path,
            timeout_in_seconds=timeout_in_seconds,
            bundle_present=False,
        )

    monkeypatch.setattr(real_spiffe, "X509Source", _make_source_without_bundle)

    with pytest.raises(SignetError, match=r"no X.509 bundle available for trust domain"):
        workload_mod.dial_workload(
            "signet.internal:8443", "unix:///tmp/agent.sock", "example.org"
        )

    # dial_workload must close the source it opened before raising, even on
    # this "connected fine, but nothing usable" failure path.
    assert _FakeX509Source.instances[0].closed is True


def test_secrets_client_returns_stub():
    from signet.v1 import secrets_pb2_grpc

    channel = grpc.insecure_channel("localhost:0")
    try:
        client = workload_mod.secrets_client(channel)
        assert isinstance(client, secrets_pb2_grpc.SecretsServiceStub)
    finally:
        channel.close()
