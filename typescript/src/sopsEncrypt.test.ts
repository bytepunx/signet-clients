// Exercises encryptForSecret against the real `sops` binary (not a
// reimplementation of SOPS's decrypt path) — this is the actual acceptance
// bar for the hand-rolled envelope format in sopsEncrypt.ts: if the AES-GCM
// nonce size, AAD, or MAC computation is even slightly wrong, `sops
// --decrypt` fails with a real decrypt error. Tests that need the binary are
// skipped (not failed) when it isn't on PATH, so this file still runs
// somewhere `sops` isn't installed.
import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as age from "age-encryption";
import { encryptForSecret } from "./sopsEncrypt.js";

function sopsAvailable(): boolean {
  const result = spawnSync("sops", ["--version"], { stdio: "ignore" });
  return !result.error && result.status === 0;
}

const haveSops = sopsAvailable();

/** Runs `sops --decrypt` against a freshly written temp file, with SOPS_AGE_KEY set to identity. */
function sopsDecrypt(content: Uint8Array, identity: string): { status: number | null; stdout: string; stderr: string } {
  const dir = mkdtempSync(join(tmpdir(), "signet-sops-test-"));
  const file = join(dir, "secret.sops.yaml");
  try {
    writeFileSync(file, content);
    const result = spawnSync("sops", ["--decrypt", file], {
      env: { ...process.env, SOPS_AGE_KEY: identity },
      encoding: "utf8",
    });
    return { status: result.status, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("encryptForSecret round-trips through the real sops binary", { skip: haveSops ? false : "sops not found on PATH" }, async () => {
  const identity = await age.generateIdentity();
  const recipient = await age.identityToRecipient(identity);

  const secretValue = "correct horse battery staple";
  const doc = await encryptForSecret(recipient, secretValue);

  const { status, stdout, stderr } = sopsDecrypt(doc, identity);
  assert.equal(status, 0, `sops --decrypt failed: ${stderr}`);

  // sops emits the decrypted document as YAML; the single field is `value`.
  assert.match(stdout, /value:\s*correct horse battery staple/);
});

test(
  "encryptForSecret produces ciphertext that fails to decrypt with the wrong identity",
  { skip: haveSops ? false : "sops not found on PATH" },
  async () => {
    const identity = await age.generateIdentity();
    const recipient = await age.identityToRecipient(identity);
    const otherIdentity = await age.generateIdentity();

    const doc = await encryptForSecret(recipient, "top secret value");

    const { status, stderr } = sopsDecrypt(doc, otherIdentity);
    assert.notEqual(status, 0, "expected sops --decrypt to fail with a non-matching identity");
    assert.ok(stderr.length > 0, "expected an error message from sops on failure");
  },
);

test("encryptForSecret rejects an empty public key", async () => {
  await assert.rejects(() => encryptForSecret("", "value"), /publicKey must not be empty/);
});

test("encryptForSecret rejects a whitespace-only public key", async () => {
  await assert.rejects(() => encryptForSecret("   ", "value"), /publicKey must not be empty/);
});

test("encryptForSecret rejects an invalid (non-age1) public key", async () => {
  await assert.rejects(() => encryptForSecret("not-a-real-age-key", "value"), /invalid age recipient/);
});
