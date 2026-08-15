//! Produces SOPS-compatible encrypted secret values.
//!
//! Mirrors `go/sops_encrypt.go`. See that file's doc comment for the full
//! rationale; the short version: `SyncBundle`/`TriggerSync` never encrypt on
//! signetd's behalf (signet's documented trust model is "only SOPS
//! ciphertext leaves the operator's machine" — see `design/draft.md` in
//! bytepunx/signet), so a plaintext value submitted via `SyncBundle` fails
//! to decrypt and is silently never stored. [`encrypt_for_secret`] is the
//! correct way to produce a value `SyncBundle` will actually persist. See
//! bytepunx/signet-clients#49.
//!
//! Implementation note: this hand-implements the narrow slice of the SOPS
//! file format needed for a single-leaf, single-age-recipient document —
//! AES-256-GCM value/MAC encryption and a SHA-512 MAC — directly on the
//! [`age`] crate (the canonical Rust age implementation) rather than
//! depending on a SOPS-format crate. The only one that exists, `rops`, is
//! pre-1.0 with open issues specifically about MAC/AAD compatibility — the
//! exact area this can't get wrong. Every other bytepunx/signet-clients
//! language hand-rolls this same logic against its own age library, for the
//! same reason (no ecosystem has a trustworthy SOPS-format library). The
//! algorithm below is verified line-for-line against
//! `github.com/getsops/sops/v3`'s own `sops.go` (`Tree.Encrypt`) and
//! `aes/cipher.go` (`Cipher.Encrypt`), and this module's tests confirm the
//! real `sops` binary can decrypt the result.

use aes_gcm::aead::consts::U32;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::aes::Aes256;
use aes_gcm::AesGcm;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::Serialize;
use sha2::{Digest, Sha512};
use std::time::SystemTime;

/// AES-256-GCM instantiated with sops's own non-standard 32-byte nonce (see
/// `github.com/getsops/sops/v3/aes.Cipher`'s `nonceSize` constant) instead
/// of the usual 12-byte GCM nonce.
type SopsAesGcm = AesGcm<Aes256, U32>;

/// The standard AES-GCM authentication tag size. A standard AEAD seal
/// appends this to the ciphertext; sops splits its output on this boundary
/// into "data" and "tag" wire-format fields.
const GCM_TAG_SIZE: usize = 16;

/// Recorded in the file's `sops.version` metadata field. The real `sops`
/// CLI only requires this to be non-empty to decrypt (it doesn't gate
/// decryption on matching its own build version).
const SOPS_FILE_VERSION: &str = "3.13.1";

/// Errors returned by [`encrypt_for_secret`].
#[derive(Debug, thiserror::Error)]
pub enum SopsEncryptError {
    /// `encrypt_for_secret` was called with an empty public key.
    #[error("signet: public key must not be empty")]
    EmptyPublicKey,

    /// The supplied public key is not a parseable age (X25519) recipient.
    #[error("signet: parse age recipient: {0}")]
    ParseRecipient(String),

    /// Encrypting the `value` leaf failed.
    #[error("signet: encrypt value: {0}")]
    EncryptValue(String),

    /// Encrypting the MAC failed.
    #[error("signet: encrypt mac: {0}")]
    EncryptMac(String),

    /// Wrapping the data key to the age recipient failed.
    #[error("signet: wrap data key: {0}")]
    WrapDataKey(String),

    /// Serializing the SOPS document to YAML failed.
    #[error("signet: marshal sops document: {0}")]
    Marshal(String),
}

#[derive(Serialize)]
struct SopsAgeKey {
    recipient: String,
    enc: String,
}

#[derive(Serialize)]
struct SopsMetadata {
    age: Vec<SopsAgeKey>,
    lastmodified: String,
    mac: String,
    version: String,
}

#[derive(Serialize)]
struct SopsDocument {
    value: String,
    sops: SopsMetadata,
}

/// Produces SOPS-compatible encrypted YAML content for `value`, encrypted
/// to `public_key` (an age recipient string, e.g. as returned by
/// `GitOpsService`'s `GetSOPSPublicKey` RPC). The result is exactly the
/// shape signetd's gitops sync path (`TriggerSync`, `SyncBundle`) and the
/// `signet secret set` CLI both expect: a YAML document with a top-level
/// `value` key, SOPS-encrypted to a single age recipient.
pub fn encrypt_for_secret(public_key: &str, value: &[u8]) -> Result<Vec<u8>, SopsEncryptError> {
    if public_key.is_empty() {
        return Err(SopsEncryptError::EmptyPublicKey);
    }
    let recipient: age::x25519::Recipient = public_key
        .parse()
        .map_err(|e: &str| SopsEncryptError::ParseRecipient(e.to_string()))?;

    let mut data_key = [0u8; 32];
    OsRng.fill_bytes(&mut data_key);

    // MAC: SHA-512 over the plaintext bytes of every leaf value, in tree
    // order (github.com/getsops/sops/v3's Tree.Encrypt + ToBytes). For our
    // fixed {value: ...} shape that's the single "value" leaf, and a plain
    // string's ToBytes is just its raw UTF-8 bytes.
    let digest = Sha512::digest(value);
    let mac_hex = hex_upper(&digest);

    let enc_value =
        sops_encrypt_leaf(&data_key, value, b"value:").map_err(SopsEncryptError::EncryptValue)?;

    let last_modified = rfc3339_now_utc();
    let enc_mac = sops_encrypt_leaf(&data_key, mac_hex.as_bytes(), last_modified.as_bytes())
        .map_err(SopsEncryptError::EncryptMac)?;

    let enc_data_key = age::encrypt_and_armor(&recipient, &data_key)
        .map_err(|e| SopsEncryptError::WrapDataKey(e.to_string()))?;

    let doc = SopsDocument {
        value: enc_value,
        sops: SopsMetadata {
            age: vec![SopsAgeKey {
                recipient: public_key.to_string(),
                enc: enc_data_key,
            }],
            lastmodified: last_modified.clone(),
            mac: enc_mac,
            version: SOPS_FILE_VERSION.to_string(),
        },
    };

    let yaml =
        serde_yaml_ng::to_string(&doc).map_err(|e| SopsEncryptError::Marshal(e.to_string()))?;

    // serde_yaml_ng infers plain (unquoted) scalar style purely from
    // whether its own bool/int/float/null resolver would misparse the
    // string on the way back in — it has no notion of YAML's timestamp
    // resolution, so an RFC3339 `lastmodified` value comes out unquoted.
    // sops's own YAML library (gopkg.in/yaml.v3) *does* implicitly resolve
    // an unquoted scalar matching that shape as `time.Time`, which then
    // fails to unmarshal into sops's string-typed `Metadata.LastModified`
    // field ("expected type 'string', got unconvertible type 'time.Time'").
    // Force it into an explicit double-quoted scalar so every YAML
    // implementation treats it as a plain string; `version` is quoted the
    // same way purely to match the real sops CLI's own output shape (it
    // isn't at risk of misresolution, since "3.13.1" isn't a valid
    // int/float/bool/timestamp).
    let yaml = force_quote_scalar(&yaml, "lastmodified", &last_modified);
    let yaml = force_quote_scalar(&yaml, "version", SOPS_FILE_VERSION);

    Ok(yaml.into_bytes())
}

/// Rewrites the single occurrence of an unquoted `"{key}: {raw_value}"`
/// scalar (as produced by serde_yaml_ng for a plain `String` field) into an
/// explicitly double-quoted one. `raw_value` is always a value this module
/// generated itself (an RFC3339 timestamp or the fixed version string), so
/// it's known not to contain characters needing escaping, and known not to
/// collide with any other line in the document (every other value is
/// base64, bech32, or an `ENC[...]` wrapper, none of which can produce the
/// exact substring `"{key}: {raw_value}"`).
fn force_quote_scalar(yaml: &str, key: &str, raw_value: &str) -> String {
    let unquoted = format!("{key}: {raw_value}");
    let quoted = format!("{key}: \"{raw_value}\"");
    yaml.replacen(&unquoted, &quoted, 1)
}

/// Encrypts `plaintext` with AES-256-GCM under `data_key` and renders it in
/// sops's own wire format, matching
/// `github.com/getsops/sops/v3/aes.Cipher.Encrypt`: a 32-byte random nonce
/// (not the usual 12 bytes), `additional_data` as GCM's AAD, and the
/// ciphertext split into "data" (everything but the last 16 bytes) and
/// "tag" (the last 16 bytes) — a standard AEAD seal appends the tag to the
/// ciphertext, sops stores them as separate base64 fields.
fn sops_encrypt_leaf(
    data_key: &[u8; 32],
    plaintext: &[u8],
    additional_data: &[u8],
) -> Result<String, String> {
    let cipher = SopsAesGcm::new(GenericArray::from_slice(data_key));

    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);

    let sealed = cipher
        .encrypt(
            GenericArray::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: additional_data,
            },
        )
        .map_err(|e| e.to_string())?;
    let (data, tag) = sealed.split_at(sealed.len() - GCM_TAG_SIZE);

    Ok(format!(
        "ENC[AES256_GCM,data:{},iv:{},tag:{},type:str]",
        BASE64.encode(data),
        BASE64.encode(nonce),
        BASE64.encode(tag),
    ))
}

/// Formats a SHA-512 digest as uppercase hex, matching Go's `fmt.Sprintf("%X", sum)`.
fn hex_upper(digest: &[u8]) -> String {
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02X}"));
    }
    out
}

/// Formats the current UTC time as RFC3339 with a `Z` suffix (e.g.
/// `2026-08-15T12:00:00Z`), matching Go's `time.Now().UTC().Format(time.RFC3339)`.
///
/// Hand-rolled on `std::time::SystemTime` rather than pulling in a
/// date/time crate (`chrono`/`time`), since this is the only place in the
/// crate that needs calendar math. Uses Howard Hinnant's well-known
/// `civil_from_days` algorithm for the Gregorian conversion:
/// <http://howardhinnant.github.io/date_algorithms.html>.
fn rfc3339_now_utc() -> String {
    let since_epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock is before the Unix epoch");
    let total_secs = since_epoch.as_secs();
    let days = (total_secs / 86_400) as i64;
    let secs_of_day = total_secs % 86_400;

    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    let (year, month, day) = civil_from_days(days);

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Converts a count of days since the Unix epoch (1970-01-01) into a
/// proleptic-Gregorian `(year, month, day)`. See
/// <http://howardhinnant.github.io/date_algorithms.html#civil_from_days>.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;
    use std::process::Command;

    #[derive(serde::Deserialize)]
    struct DecryptedDoc {
        value: String,
    }

    /// The core correctness check: content produced by `encrypt_for_secret`
    /// must be decryptable by the real `sops` binary (the same tool
    /// signetd's own server-side decrypt path is compatible with), not just
    /// self-consistent with this module's own code.
    #[test]
    fn encrypt_for_secret_real_sops_can_decrypt() {
        let Ok(sops_path) = which_sops() else {
            eprintln!("sops binary not found on PATH; skipping real-sops round-trip test");
            return;
        };

        let identity = age::x25519::Identity::generate();
        let encrypted = encrypt_for_secret(&identity.to_public().to_string(), b"hello-world")
            .expect("encrypt_for_secret");

        let dir = tempdir();
        let secret_path = dir.join("secret.yaml");
        std::fs::write(&secret_path, &encrypted).expect("write encrypted file");

        let output = Command::new(&sops_path)
            .arg("--decrypt")
            .arg(&secret_path)
            .env("SOPS_AGE_KEY", identity.to_string().expose_secret())
            .output()
            .expect("run sops");
        assert!(
            output.status.success(),
            "sops decrypt failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let doc: DecryptedDoc =
            serde_yaml_ng::from_slice(&output.stdout).expect("parse decrypted yaml");
        assert_eq!(doc.value, "hello-world");
    }

    /// Verifies the real `sops` binary rejects decryption with an identity
    /// that wasn't encrypted to — i.e. that `encrypt_for_secret` is
    /// actually scoping access to the given recipient, not producing
    /// something any identity can open.
    #[test]
    fn encrypt_for_secret_wrong_identity_fails() {
        let Ok(sops_path) = which_sops() else {
            eprintln!("sops binary not found on PATH; skipping real-sops round-trip test");
            return;
        };

        let encrypted_to = age::x25519::Identity::generate();
        let wrong_identity = age::x25519::Identity::generate();

        let encrypted = encrypt_for_secret(&encrypted_to.to_public().to_string(), b"hello-world")
            .expect("encrypt_for_secret");

        let dir = tempdir();
        let secret_path = dir.join("secret.yaml");
        std::fs::write(&secret_path, &encrypted).expect("write encrypted file");

        let output = Command::new(&sops_path)
            .arg("--decrypt")
            .arg(&secret_path)
            .env("SOPS_AGE_KEY", wrong_identity.to_string().expose_secret())
            .output()
            .expect("run sops");
        assert!(
            !output.status.success(),
            "expected sops decrypt with the wrong identity to fail, got: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    /// Verifies the empty-input case is rejected explicitly rather than
    /// failing deeper inside the age library with a less obvious error.
    #[test]
    fn encrypt_for_secret_empty_public_key() {
        let err = encrypt_for_secret("", b"hello-world").expect_err("expected an error");
        assert!(matches!(err, SopsEncryptError::EmptyPublicKey));
    }

    /// Verifies a malformed recipient string is rejected clearly rather
    /// than producing a file that silently can't be decrypted by anyone.
    #[test]
    fn encrypt_for_secret_invalid_public_key() {
        let err = encrypt_for_secret("not-a-real-age-key", b"hello-world")
            .expect_err("expected an error");
        assert!(matches!(err, SopsEncryptError::ParseRecipient(_)));
    }

    fn which_sops() -> Result<String, ()> {
        let output = Command::new("which").arg("sops").output().map_err(|_| ())?;
        if !output.status.success() {
            return Err(());
        }
        String::from_utf8(output.stdout)
            .map(|s| s.trim().to_string())
            .map_err(|_| ())
    }

    /// A minimal per-test temp directory, without pulling in the `tempfile`
    /// crate as a dev-dependency for a single test module.
    fn tempdir() -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        let unique = format!(
            "signet-sops-encrypt-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        dir.push(unique);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }
}
