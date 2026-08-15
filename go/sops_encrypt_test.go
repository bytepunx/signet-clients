package signet

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"gopkg.in/yaml.v3"
)

// TestEncryptForSecret_RealSopsCanDecrypt is the core correctness check:
// content produced by EncryptForSecret must be decryptable by the real sops
// binary (the same tool signetd's own server-side DecryptFile is compatible
// with), not just self-consistent with this package's own code. Skips if
// sops isn't on PATH, matching the precedent in bytepunx/signet's own
// TestDecryptFile_RealSopsCiphertext.
func TestEncryptForSecret_RealSopsCanDecrypt(t *testing.T) {
	sopsPath, err := exec.LookPath("sops")
	if err != nil {
		t.Skip("sops binary not found on PATH; skipping real-sops round-trip test")
	}

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate age identity: %v", err)
	}

	encrypted, err := EncryptForSecret(identity.Recipient().String(), []byte("hello-world"))
	if err != nil {
		t.Fatalf("EncryptForSecret: %v", err)
	}

	dir := t.TempDir()
	secretPath := filepath.Join(dir, "secret.yaml")
	if err := os.WriteFile(secretPath, encrypted, 0o600); err != nil {
		t.Fatalf("write encrypted file: %v", err)
	}

	cmd := exec.Command(sopsPath, "--decrypt", secretPath)
	cmd.Env = append(os.Environ(), "SOPS_AGE_KEY="+identity.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sops decrypt failed: %s: %v", out, err)
	}

	var doc struct {
		Value string `yaml:"value"`
	}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("parse decrypted yaml: %v", err)
	}
	if doc.Value != "hello-world" {
		t.Fatalf("decrypted value = %q, want %q", doc.Value, "hello-world")
	}
}

// TestEncryptForSecret_WrongIdentityFails verifies the real sops binary
// rejects decryption with an identity that wasn't encrypted to — i.e. that
// EncryptForSecret is actually scoping access to the given recipient, not
// producing something any identity can open.
func TestEncryptForSecret_WrongIdentityFails(t *testing.T) {
	sopsPath, err := exec.LookPath("sops")
	if err != nil {
		t.Skip("sops binary not found on PATH; skipping real-sops round-trip test")
	}

	encryptedTo, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate age identity: %v", err)
	}
	wrongIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate age identity: %v", err)
	}

	encrypted, err := EncryptForSecret(encryptedTo.Recipient().String(), []byte("hello-world"))
	if err != nil {
		t.Fatalf("EncryptForSecret: %v", err)
	}

	dir := t.TempDir()
	secretPath := filepath.Join(dir, "secret.yaml")
	if err := os.WriteFile(secretPath, encrypted, 0o600); err != nil {
		t.Fatalf("write encrypted file: %v", err)
	}

	cmd := exec.Command(sopsPath, "--decrypt", secretPath)
	cmd.Env = append(os.Environ(), "SOPS_AGE_KEY="+wrongIdentity.String())
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("expected sops decrypt with the wrong identity to fail, got: %s", out)
	}
}

// TestEncryptForSecret_EmptyPublicKey verifies the empty-input case is
// rejected explicitly rather than failing deeper inside the sops library
// with a less obvious error.
func TestEncryptForSecret_EmptyPublicKey(t *testing.T) {
	if _, err := EncryptForSecret("", []byte("hello-world")); err == nil {
		t.Fatal("expected an error for an empty public key, got nil")
	}
}

// TestEncryptForSecret_InvalidPublicKey verifies a malformed recipient
// string is rejected clearly rather than producing a file that silently
// can't be decrypted by anyone.
func TestEncryptForSecret_InvalidPublicKey(t *testing.T) {
	if _, err := EncryptForSecret("not-a-real-age-key", []byte("hello-world")); err == nil {
		t.Fatal("expected an error for a malformed public key, got nil")
	}
}
