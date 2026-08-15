package signet

import (
	"crypto/rand"
	"fmt"

	sops "github.com/getsops/sops/v3"
	sopsaes "github.com/getsops/sops/v3/aes"
	sopsage "github.com/getsops/sops/v3/age"
	sopscommon "github.com/getsops/sops/v3/cmd/sops/common"
	sopsconfig "github.com/getsops/sops/v3/config"
	sopsyaml "github.com/getsops/sops/v3/stores/yaml"
	"gopkg.in/yaml.v3"
)

// sopsDataKeySize is the size, in bytes, of the random AES-256 data key SOPS
// generates per file — matches sops's own Tree.GenerateDataKeyWithKeyServices.
const sopsDataKeySize = 32

// sopsFileVersion is recorded in the file's "sops.version" metadata field.
// The real sops CLI only requires this to be non-empty to decrypt (it
// doesn't gate decryption on matching its own build version); pinned to the
// getsops/sops/v3 release this package builds against rather than importing
// that module's own version package, which pulls in a full CLI framework
// (github.com/urfave/cli) for a single string constant.
const sopsFileVersion = "3.13.1"

// EncryptForSecret produces SOPS-compatible encrypted YAML content for value,
// encrypted to publicKey (an age recipient string, e.g. as returned by
// GitOpsService's GetSOPSPublicKey RPC). The result is exactly the shape
// signetd's gitops sync path (TriggerSync, SyncBundle) and the `signet
// secret set` CLI both expect: a YAML document with a top-level "value" key,
// SOPS-encrypted to a single age recipient.
//
// This exists because SyncBundle stores secret file content as-is — it never
// encrypts on the server's behalf (see design/draft.md's "only SOPS
// ciphertext leaves the operator's machine" trust model in bytepunx/signet).
// A plaintext value submitted via SyncBundle fails to decrypt and is
// silently never stored; EncryptForSecret is the correct way to produce a
// value SyncBundle will actually persist. See bytepunx/signet-clients#49.
//
// No external sops binary is required: this uses the same
// github.com/getsops/sops/v3 + filippo.io/age libraries signetd's own
// server-side decrypt path already depends on, run in the encrypt
// direction — a library needing a binary on PATH is a worse story than a
// CLI needing one, which is why `signet secret set` (CLI-only) can get away
// with shelling out but this can't.
func EncryptForSecret(publicKey string, value []byte) ([]byte, error) {
	if publicKey == "" {
		return nil, fmt.Errorf("signet: public key must not be empty")
	}

	mk, err := sopsage.MasterKeyFromRecipient(publicKey)
	if err != nil {
		return nil, fmt.Errorf("signet: parse age recipient: %w", err)
	}

	dataKey := make([]byte, sopsDataKeySize)
	if _, err := rand.Read(dataKey); err != nil {
		return nil, fmt.Errorf("signet: generate data key: %w", err)
	}
	if err := mk.Encrypt(dataKey); err != nil {
		return nil, fmt.Errorf("signet: encrypt data key: %w", err)
	}

	plain, err := yaml.Marshal(map[string]string{"value": string(value)})
	if err != nil {
		return nil, fmt.Errorf("signet: marshal plaintext yaml: %w", err)
	}

	store := sopsyaml.NewStore(&sopsconfig.YAMLStoreConfig{})
	branches, err := store.LoadPlainFile(plain)
	if err != nil {
		return nil, fmt.Errorf("signet: load plaintext yaml: %w", err)
	}

	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups: []sops.KeyGroup{{mk}},
			Version:   sopsFileVersion,
		},
	}

	if err := sopscommon.EncryptTree(sopscommon.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    &tree,
		Cipher:  sopsaes.NewCipher(),
	}); err != nil {
		return nil, fmt.Errorf("signet: encrypt tree: %w", err)
	}

	encrypted, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("signet: emit encrypted file: %w", err)
	}
	return encrypted, nil
}
