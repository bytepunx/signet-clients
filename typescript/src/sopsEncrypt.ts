// encryptForSecret hand-implements the narrow slice of the SOPS encrypted-file
// format signetd requires: a single `value: <ciphertext>` leaf, encrypted to
// exactly one age (X25519) recipient. This exists because signetd never
// encrypts secrets on a caller's behalf — SyncBundle/TriggerSync both require
// content that is already real SOPS ciphertext (signet's documented trust
// model is "only SOPS ciphertext leaves the operator's machine") — and no npm
// package implements the actual SOPS envelope format (everything under
// "sops" on npm is either decrypt-only or produces an incompatible custom
// format). See bytepunx/signet-clients#49.
//
// The algorithm below was verified against the github.com/getsops/sops/v3
// source and cross-checked by round-tripping output through the real `sops`
// binary (see sopsEncrypt.test.ts) — follow it precisely; do not improvise.
import { createCipheriv, createHash, randomBytes } from "node:crypto";
import { Encrypter, armor } from "age-encryption";
import { Document, Scalar } from "yaml";

const SOPS_VERSION = "3.13.1";

/**
 * encryptForSecret produces a SOPS-compatible encrypted YAML document for a
 * single secret value, encrypted to the given age recipient (a `age1...`
 * public key string, e.g. from signetd's GetSOPSPublicKey RPC). The result is
 * byte-for-byte suitable as the `content` of a signet SyncBundle/TriggerSync
 * call — decrypting it with `sops --decrypt` (given the matching age
 * identity) recovers a document with exactly one field, `value`, holding the
 * original secret.
 *
 * value may be a UTF-8 string or raw bytes; either way it is encrypted and
 * MAC'd as-is (this mirrors what `sops --encrypt` produces for a file
 * containing exactly `value: "<secret>"`, always rendered as SOPS's `str`
 * leaf type).
 */
export async function encryptForSecret(publicKey: string, value: string | Uint8Array): Promise<Uint8Array> {
  const recipient = publicKey.trim();
  if (recipient === "") {
    throw new Error("signet: encryptForSecret: publicKey must not be empty");
  }

  const plaintext = typeof value === "string" ? Buffer.from(value, "utf8") : Buffer.from(value);

  const dataKey = randomBytes(32);

  const mac = createHash("sha512").update(plaintext).digest("hex").toUpperCase();

  const encryptedValue = gcmSealSopsEnc(dataKey, plaintext, "value:");

  // Whole-second precision, no fractional digits: sops parses lastmodified
  // back into a Go time.Time and re-derives the MAC's AAD by reformatting it
  // with Go's time.RFC3339 layout, which always truncates to whole seconds —
  // date.toISOString() always includes millisecond digits (".000Z"), so
  // leaving them in here would make the AAD sops recomputes at decrypt time
  // disagree with the one used below, and MAC decryption would fail
  // authentication.
  const lastmodified = new Date().toISOString().replace(/\.\d+Z$/, "Z");
  const encryptedMac = gcmSealSopsEnc(dataKey, Buffer.from(mac, "utf8"), lastmodified);

  const encrypter = new Encrypter();
  try {
    encrypter.addRecipient(recipient);
  } catch (err) {
    throw new Error(`signet: encryptForSecret: invalid age recipient: ${err instanceof Error ? err.message : String(err)}`);
  }
  const wrappedDataKey = await encrypter.encrypt(dataKey);
  const armoredDataKey = armor.encode(wrappedDataKey);

  const doc = new Document({
    value: encryptedValue,
    sops: {
      age: [
        {
          recipient,
          enc: armoredDataKey,
        },
      ],
      lastmodified,
      mac: encryptedMac,
      version: SOPS_VERSION,
    },
  });

  // lastmodified must round-trip as a plain string. Go's yaml.v3 (which sops
  // is built on) auto-detects an *unquoted* RFC3339 scalar as a time.Time
  // when decoding, which then fails to unmarshal into sops's Metadata.
  // LastModified string field ("expected type 'string', got unconvertible
  // type 'time.Time'") — force double-quoted style so it round-trips as a
  // string regardless of the parser's schema.
  const lastmodifiedNode = doc.getIn(["sops", "lastmodified"], true);
  if (lastmodifiedNode instanceof Scalar) {
    lastmodifiedNode.type = Scalar.QUOTE_DOUBLE;
  }

  return new TextEncoder().encode(doc.toString());
}

/**
 * gcmSealSopsEnc encrypts plaintext with AES-256-GCM under a fresh random
 * 32-byte nonce (not the standard 12 bytes — this matches sops's own
 * `cipher.NewGCMWithNonceSize(cipher, 32)`), authenticating aad, and renders
 * the result in sops's `ENC[...]` leaf syntax.
 */
function gcmSealSopsEnc(dataKey: Buffer, plaintext: Buffer, aad: string): string {
  const nonce = randomBytes(32);
  const cipher = createCipheriv("aes-256-gcm", dataKey, nonce);
  cipher.setAAD(Buffer.from(aad, "utf8"));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return `ENC[AES256_GCM,data:${ciphertext.toString("base64")},iv:${nonce.toString("base64")},tag:${tag.toString("base64")},type:str]`;
}
