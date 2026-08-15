"""Tests for signet_client.sops_encrypt's encrypt_for_secret.

The core correctness test shells out to the real `sops` binary to decrypt
what encrypt_for_secret produces — this is the actual acceptance bar for a
hand-rolled implementation of SOPS' envelope format: if the AES-GCM nonce
size, AAD, or MAC computation is even slightly wrong, `sops --decrypt` fails
with a real error from the real tool, not just a lenient re-implementation
of our own encoder agreeing with itself. Skipped (not failed) if `sops`
isn't on PATH, since it's an external binary this repo doesn't vendor.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from pyrage import x25519

from signet_client.sops_encrypt import encrypt_for_secret

_SOPS_BIN = shutil.which("sops")

requires_sops = pytest.mark.skipif(
    _SOPS_BIN is None, reason="real `sops` binary not found on PATH"
)


def _generate_identity() -> tuple[str, str]:
    """Returns (secret_key_str, public_key_str) for a fresh age identity."""
    identity = x25519.Identity.generate()
    return str(identity), str(identity.to_public())


def _sops_decrypt(doc: bytes, secret_key: str) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "secret.sops.yaml"
        path.write_bytes(doc)
        env = {**os.environ, "SOPS_AGE_KEY": secret_key}
        return subprocess.run(
            [_SOPS_BIN, "--decrypt", str(path)],
            env=env,
            capture_output=True,
            text=True,
        )


@requires_sops
def test_encrypt_for_secret_round_trips_through_real_sops_binary():
    secret_key, public_key = _generate_identity()

    doc = encrypt_for_secret(public_key, "correct horse battery staple")
    assert isinstance(doc, bytes)

    result = _sops_decrypt(doc, secret_key)
    assert result.returncode == 0, (
        f"sops --decrypt failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    )

    # `sops --decrypt` on a single-key document prints the decrypted value
    # of that key (bare, for a lone `value` key sops emits `value: "..."`
    # by default unless --output-type is overridden — assert on the
    # substring rather than an exact parse to stay robust to sops' own
    # default output formatting).
    assert "correct horse battery staple" in result.stdout


@requires_sops
def test_encrypt_for_secret_round_trips_bytes_value():
    secret_key, public_key = _generate_identity()

    doc = encrypt_for_secret(public_key, b"raw-bytes-secret-value")

    result = _sops_decrypt(doc, secret_key)
    assert result.returncode == 0, (
        f"sops --decrypt failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    assert "raw-bytes-secret-value" in result.stdout


@requires_sops
def test_encrypt_for_secret_fails_to_decrypt_with_wrong_identity():
    _secret_key, public_key = _generate_identity()
    wrong_secret_key, _wrong_public_key = _generate_identity()

    doc = encrypt_for_secret(public_key, "top secret value")

    result = _sops_decrypt(doc, wrong_secret_key)
    assert result.returncode != 0
    assert "top secret value" not in result.stdout


def test_encrypt_for_secret_rejects_empty_public_key():
    with pytest.raises(ValueError, match="public_key"):
        encrypt_for_secret("", "some-value")


def test_encrypt_for_secret_rejects_whitespace_only_public_key():
    with pytest.raises(ValueError, match="public_key"):
        encrypt_for_secret("   ", "some-value")


def test_encrypt_for_secret_rejects_invalid_public_key():
    with pytest.raises(ValueError, match="public_key"):
        encrypt_for_secret("not-an-age-key", "some-value")


def test_encrypt_for_secret_rejects_wrong_key_type():
    # A syntactically-plausible-but-wrong string (e.g. an ssh key or garbage
    # bech32) should still be rejected with a clear ValueError, not an
    # opaque pyrage exception leaking out.
    with pytest.raises(ValueError, match="public_key"):
        encrypt_for_secret("age1", "some-value")


def test_encrypt_for_secret_output_is_parseable_yaml_with_expected_shape():
    from ruamel.yaml import YAML

    _secret_key, public_key = _generate_identity()
    doc = encrypt_for_secret(public_key, "shape-check-value")

    yaml = YAML(typ="safe")
    parsed = yaml.load(doc)

    assert parsed["value"].startswith("ENC[AES256_GCM,")
    assert parsed["value"].endswith("type:str]")

    sops = parsed["sops"]
    assert sops["version"]
    assert sops["mac"].startswith("ENC[AES256_GCM,")
    assert sops["lastmodified"].endswith("Z")

    age_entries = sops["age"]
    assert len(age_entries) == 1
    assert age_entries[0]["recipient"] == public_key
    assert "-----BEGIN AGE ENCRYPTED FILE-----" in age_entries[0]["enc"]
    assert "-----END AGE ENCRYPTED FILE-----" in age_entries[0]["enc"]
