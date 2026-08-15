package signet

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"gopkg.in/yaml.v3"
)

// sopsFileVersion is recorded in the file's "sops.version" metadata field.
// The real sops CLI only requires this to be non-empty to decrypt (it
// doesn't gate decryption on matching its own build version).
const sopsFileVersion = "3.13.1"

// gcmNonceSize matches sops's own non-standard 32-byte AES-GCM nonce (see
// github.com/getsops/sops/v3/aes.Cipher's nonceSize constant) — not the
// usual 12-byte GCM nonce.
const gcmNonceSize = 32

// gcmTagSize is the standard AES-GCM authentication tag size, appended by
// Go's cipher.AEAD.Seal after the ciphertext; sops splits its output on
// this boundary into "data" and "tag" wire-format fields.
const gcmTagSize = 16

type sopsAgeKey struct {
	Recipient string `yaml:"recipient"`
	Enc       string `yaml:"enc"`
}

type sopsMetadata struct {
	Age          []sopsAgeKey `yaml:"age"`
	LastModified string       `yaml:"lastmodified"`
	MAC          string       `yaml:"mac"`
	Version      string       `yaml:"version"`
}

type sopsDocument struct {
	Value string       `yaml:"value"`
	Sops  sopsMetadata `yaml:"sops"`
}

// EncryptForSecret produces SOPS-compatible encrypted YAML content for
// value, encrypted to publicKey (an age recipient string, e.g. as returned
// by GitOpsService's GetSOPSPublicKey RPC). The result is exactly the shape
// signetd's gitops sync path (TriggerSync, SyncBundle) and the `signet
// secret set` CLI both expect: a YAML document with a top-level "value"
// key, SOPS-encrypted to a single age recipient.
//
// This exists because SyncBundle stores secret file content as-is — it never
// encrypts on the server's behalf (see design/draft.md's "only SOPS
// ciphertext leaves the operator's machine" trust model in bytepunx/signet).
// A plaintext value submitted via SyncBundle fails to decrypt and is
// silently never stored; EncryptForSecret is the correct way to produce a
// value SyncBundle will actually persist. See bytepunx/signet-clients#49.
//
// Implementation note: this hand-implements the narrow slice of the SOPS
// file format needed for a single-leaf, single-age-recipient document —
// AES-256-GCM value/MAC encryption and a SHA-512 MAC — directly on
// filippo.io/age (the reference age implementation, and the library
// signetd's own server-side decrypt path already depends on) rather than
// importing github.com/getsops/sops/v3. That module's Tree/Metadata
// abstraction unconditionally pulls in every backend it supports (PGP, AWS
// KMS, GCP KMS, Azure Key Vault, HashiCorp Vault) even though we only ever
// use age, which is a large, unjustifiable dependency footprint for a
// client library. Every other bytepunx/signet-clients language has to
// hand-roll this same logic (no other ecosystem has a trustworthy
// SOPS-format library either), so this keeps one consistent approach
// across all of them instead of Go being the odd one out. The algorithm
// below is verified line-for-line against github.com/getsops/sops/v3's own
// sops.go (Tree.Encrypt) and aes/cipher.go (Cipher.Encrypt), and this
// package's tests confirm the real sops binary can decrypt the result.
func EncryptForSecret(publicKey string, value []byte) ([]byte, error) {
	if publicKey == "" {
		return nil, fmt.Errorf("signet: public key must not be empty")
	}
	recipient, err := age.ParseX25519Recipient(publicKey)
	if err != nil {
		return nil, fmt.Errorf("signet: parse age recipient: %w", err)
	}

	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		return nil, fmt.Errorf("signet: generate data key: %w", err)
	}

	// MAC: SHA-512 over the plaintext bytes of every leaf value, in tree
	// order (github.com/getsops/sops/v3's Tree.Encrypt + ToBytes). For our
	// fixed {value: ...} shape that's the single "value" leaf, and a plain
	// string's ToBytes is just its raw UTF-8 bytes.
	sum := sha512.Sum512(value)
	macHex := fmt.Sprintf("%X", sum)

	encValue, err := sopsEncryptLeaf(dataKey, value, "value:")
	if err != nil {
		return nil, fmt.Errorf("signet: encrypt value: %w", err)
	}

	lastModified := time.Now().UTC().Format(time.RFC3339)
	encMAC, err := sopsEncryptLeaf(dataKey, []byte(macHex), lastModified)
	if err != nil {
		return nil, fmt.Errorf("signet: encrypt mac: %w", err)
	}

	encDataKey, err := ageEncryptDataKey(dataKey, recipient)
	if err != nil {
		return nil, fmt.Errorf("signet: wrap data key: %w", err)
	}

	doc := sopsDocument{
		Value: encValue,
		Sops: sopsMetadata{
			Age: []sopsAgeKey{{
				Recipient: publicKey,
				Enc:       encDataKey,
			}},
			LastModified: lastModified,
			MAC:          encMAC,
			Version:      sopsFileVersion,
		},
	}

	out, err := yaml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("signet: marshal sops document: %w", err)
	}
	return out, nil
}

// sopsEncryptLeaf encrypts plaintext with AES-256-GCM under dataKey and
// renders it in sops's own wire format, matching
// github.com/getsops/sops/v3/aes.Cipher.Encrypt: a 32-byte random nonce
// (not the usual 12 bytes), additionalData as GCM's AAD, and the ciphertext
// split into "data" (everything but the last 16 bytes) and "tag" (the last
// 16 bytes) — Go's cipher.AEAD.Seal appends the tag to the ciphertext, sops
// stores them as separate base64 fields.
func sopsEncryptLeaf(dataKey, plaintext []byte, additionalData string) (string, error) {
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, gcmNonceSize)
	if err != nil {
		return "", err
	}
	iv := make([]byte, gcmNonceSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, iv, plaintext, []byte(additionalData))
	data := sealed[:len(sealed)-gcmTagSize]
	tag := sealed[len(sealed)-gcmTagSize:]
	return fmt.Sprintf("ENC[AES256_GCM,data:%s,iv:%s,tag:%s,type:str]",
		base64.StdEncoding.EncodeToString(data),
		base64.StdEncoding.EncodeToString(iv),
		base64.StdEncoding.EncodeToString(tag),
	), nil
}

// ageEncryptDataKey wraps dataKey to recipient as an ASCII-armored age
// file — the exact form SOPS embeds in the "enc" field of a sops.age[]
// entry (mirrors github.com/getsops/sops/v3/age.MasterKey.Encrypt, which
// does the same thing via the same filippo.io/age APIs).
func ageEncryptDataKey(dataKey []byte, recipient age.Recipient) (string, error) {
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, recipient)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(dataKey); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	if err := aw.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}
