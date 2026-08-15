"""Produces real SOPS-compatible ciphertext for a single secret value.

signetd (bytepunx/signet) never encrypts secrets on the client's behalf —
``SyncBundle``/``TriggerSync`` require content that is already real SOPS
ciphertext, and signet's documented trust model is "only SOPS ciphertext
leaves the operator's machine." This module hand-implements the narrow slice
of the SOPS envelope format needed to produce that ciphertext for a single
``value: "<secret>"`` document encrypted to exactly one age (X25519)
recipient, equivalent to what ``sops --encrypt`` produces for that shape of
file.

No PyPI package implements the actual SOPS envelope format: the old ``sops``
package is dead and PGP-only, and everything else either shells out to the
real ``sops`` binary or is decrypt-only. This builds directly on ``pyrage``
(PyO3 bindings to the Rust ``rage`` crate) for the age-encryption primitive,
plus ``cryptography`` (already a dependency, see ``admin.py``) for the
AES-256-GCM leaf/MAC encryption, matching the exact scheme SOPS itself uses
(verified against github.com/getsops/sops/v3's source and the real ``sops``
binary — see this repo's Go reference implementation and
python/tests/test_sops_encrypt.py, which round-trips output through the real
``sops`` binary).

This intentionally does not implement: multiple recipients, multiple keys
(PGP/KMS/age), nested/multi-key documents, or any tree shape beyond a single
top-level ``value`` string leaf — signet only ever needs to produce a
one-value, one-recipient secret.
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
from datetime import datetime, timezone

import pyrage
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import LiteralScalarString

__all__ = ["encrypt_for_secret"]

# sops only checks that this field is a non-empty string; it doesn't gate on
# it matching sops' own build version. Pinned to the sops release this
# implementation was verified against.
_SOPS_VERSION = "3.13.1"

_VALUE_AAD = b"value:"


def encrypt_for_secret(public_key: str, value: bytes | str) -> bytes:
    """Encrypts ``value`` into a SOPS-compatible YAML document under the key
    ``value``, encrypted to the single age (X25519) recipient ``public_key``
    (an ``age1...`` string, as returned by signet's ``GetSOPSPublicKey``
    admin RPC).

    The returned bytes are a complete SOPS YAML file — exactly the shape
    ``sops --encrypt`` produces for a file containing only ``value: "..."``
    — suitable for passing directly as the content of a
    ``SyncBundle``/``TriggerSync`` secret. It can be decrypted with the real
    ``sops`` binary (``sops --decrypt``) given the matching age identity.

    Raises:
        ValueError: if ``public_key`` is empty/whitespace-only or is not a
            valid age (X25519) recipient string.
    """
    if not public_key or not public_key.strip():
        raise ValueError("signet: public_key must not be empty")

    try:
        recipient = pyrage.x25519.Recipient.from_str(public_key.strip())
    except Exception as e:
        raise ValueError(
            f"signet: public_key is not a valid age recipient: {e}"
        ) from e

    if isinstance(value, str):
        plaintext = value.encode("utf-8")
    else:
        plaintext = value

    data_key = os.urandom(32)

    # MAC: SHA-512 of the raw plaintext bytes (sops' ToBytes for a string is
    # just its bytes — for our fixed single-leaf shape that's the entire MAC
    # input, no separators), uppercase hex.
    mac_hex = hashlib.sha512(plaintext).hexdigest().upper()

    value_enc = _sops_aes_gcm_encrypt(data_key, plaintext, _VALUE_AAD)

    last_modified = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    mac_enc = _sops_aes_gcm_encrypt(
        data_key, mac_hex.encode("utf-8"), last_modified.encode("utf-8")
    )

    armored_key = pyrage.encrypt(data_key, [recipient], armored=True).decode("ascii")

    document = {
        "value": value_enc,
        "sops": {
            "age": [
                {
                    "recipient": public_key.strip(),
                    "enc": LiteralScalarString(armored_key),
                }
            ],
            "lastmodified": last_modified,
            "mac": mac_enc,
            "version": _SOPS_VERSION,
        },
    }

    yaml = YAML()
    yaml.default_flow_style = False
    yaml.indent(mapping=4, sequence=4, offset=2)
    buf = io.StringIO()
    yaml.dump(document, buf)
    return buf.getvalue().encode("utf-8")


def _sops_aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> str:
    """AES-256-GCM with sops' non-standard 32-byte nonce, rendered as sops'
    ``ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]`` format.
    """
    nonce = os.urandom(32)
    ct_and_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
    ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    return (
        "ENC[AES256_GCM,"
        f"data:{base64.b64encode(ciphertext).decode('ascii')},"
        f"iv:{base64.b64encode(nonce).decode('ascii')},"
        f"tag:{base64.b64encode(tag).decode('ascii')},"
        "type:str]"
    )
