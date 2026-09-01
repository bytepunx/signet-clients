// Tests for the hand-rolled pieces of the SPIFFE workload path: trust-domain
// authorization (mirroring go-spiffe's tlsconfig.AuthorizeMemberOf) and
// DER-to-PEM conversion. These are the two pieces this library had to
// reimplement itself because no maintained Node SPIFFE library provides
// them (see ../README.md). No real certificate material, socket, or SPIRE
// instance is involved — authorizeTrustDomainMember is exercised against
// hand-written fake PeerCertificate-shaped objects.
//
// The credentialsFromSVID/workloadChannelCredentials coverage further down
// (bytepunx/signet-clients gitops-workload-mtls-examples) is the exception:
// grpc-js's ChannelCredentials.createSsl calls straight into Node's
// tls.createSecureContext, which really does parse the PEM it's given, and
// parseCertificateBundle (from `spiffe`) does real ASN.1 DER parsing before
// that — hand-written fake bytes wouldn't survive either step the way a fake
// PeerCertificate survives authorizeTrustDomainMember. generateSelfSignedSVID
// below builds one real (if minimal) self-signed certificate via
// @peculiar/x509 for that reason. Still no socket or SPIRE instance: this
// never calls dialWorkload/workloadChannelCredentials's SVID-fetch path,
// only the pure credential-building step downstream of a (fabricated) SVID.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import type { PeerCertificate } from "node:tls";
import { Crypto } from "@peculiar/webcrypto";
import * as x509 from "@peculiar/x509";
import type { X509SVID } from "spiffe";
import { AdminServiceClient, GitOpsServiceClient } from "./gen/admin/v1/admin.js";
import { SecretsServiceClient } from "./gen/signet/v1/secrets.js";
import {
  authorizeTrustDomainMember,
  credentialsFromSVID,
  derToPem,
  isNoIdentityIssuedErr,
  retryUntilIdentityIssued,
  workloadChannelCredentials,
  workloadDialBackoffMs,
  workloadDialMaxAttempts,
} from "./workload.js";

function fakeCert(subjectaltname: string | undefined): PeerCertificate {
  return { subjectaltname } as PeerCertificate;
}

test("authorizeTrustDomainMember accepts a server presenting a SPIFFE ID in the expected trust domain", () => {
  const verify = authorizeTrustDomainMember("example.org");
  const err = verify("ignored-hostname", fakeCert("URI:spiffe://example.org/ns/default/sa/signet"));
  assert.equal(err, undefined);
});

test("authorizeTrustDomainMember accepts when the SAN list has other entries too", () => {
  const verify = authorizeTrustDomainMember("example.org");
  const err = verify(
    "ignored-hostname",
    fakeCert("DNS:signet.internal, URI:spiffe://example.org/ns/default/sa/signet, IP Address:10.0.0.1"),
  );
  assert.equal(err, undefined);
});

test("authorizeTrustDomainMember rejects a SPIFFE ID from a different trust domain with a clear message", () => {
  const verify = authorizeTrustDomainMember("example.org");
  const err = verify("ignored-hostname", fakeCert("URI:spiffe://evil.example/ns/default/sa/signet"));
  assert.ok(err instanceof Error);
  assert.match(err!.message, /trust domain "evil\.example"/);
  assert.match(err!.message, /expected trust domain "example\.org"/);
});

test("authorizeTrustDomainMember rejects a certificate with no SPIFFE URI SAN", () => {
  const verify = authorizeTrustDomainMember("example.org");
  const err = verify("ignored-hostname", fakeCert("DNS:signet.internal"));
  assert.ok(err instanceof Error);
  assert.match(err!.message, /did not present a SPIFFE ID/);
});

test("authorizeTrustDomainMember rejects a certificate with no subjectaltname at all", () => {
  const verify = authorizeTrustDomainMember("example.org");
  const err = verify("ignored-hostname", fakeCert(undefined));
  assert.ok(err instanceof Error);
  assert.match(err!.message, /did not present a SPIFFE ID/);
});

test("authorizeTrustDomainMember normalizes a spiffe:// scheme prefix on the expected trust domain", () => {
  const verify = authorizeTrustDomainMember("spiffe://example.org");
  const err = verify("ignored-hostname", fakeCert("URI:spiffe://example.org/ns/default/sa/signet"));
  assert.equal(err, undefined);
});

test("authorizeTrustDomainMember rejects an empty expected trust domain up front", () => {
  assert.throws(() => authorizeTrustDomainMember("  "), /trust domain must not be empty/);
});

test("authorizeTrustDomainMember rejects an expected trust domain containing a path", () => {
  assert.throws(() => authorizeTrustDomainMember("example.org/ns/default"), /must not contain a path/);
});

test("derToPem wraps base64 with the given PEM label and 64-column lines", () => {
  const der = Buffer.from("this is definitely not real DER, just test bytes for wrapping".repeat(2), "utf8");
  const pem = derToPem(der, "PRIVATE KEY");

  assert.match(pem, /^-----BEGIN PRIVATE KEY-----\n/);
  assert.match(pem, /-----END PRIVATE KEY-----\n$/);

  const body = pem
    .replace("-----BEGIN PRIVATE KEY-----\n", "")
    .replace("-----END PRIVATE KEY-----\n", "")
    .split("\n")
    .filter((line) => line.length > 0);
  for (const line of body.slice(0, -1)) {
    assert.equal(line.length, 64, `expected 64-char lines, got ${line.length}: ${line}`);
  }

  const roundTripped = Buffer.from(body.join(""), "base64");
  assert.ok(roundTripped.equals(der), "expected base64 round-trip to reproduce the original DER bytes");
});

// ---------------------------------------------------------------------------
// GitOps-over-workload-mTLS credential exposure
// (bytepunx/signet-clients gitops-workload-mtls-examples, bytepunx/signet#23,
// #38, #78)
//
// dialWorkload used to build its ChannelCredentials internally and never
// hand them back, so a caller who wanted a GitOpsServiceClient/
// AdminServiceClient authenticated the same way had no way to get there
// short of duplicating the whole SVID-fetch-with-retry + credential-build
// dance themselves. workloadChannelCredentials is that step, exported
// standalone; dialWorkload now calls it internally (proving existing
// callers see no behavior change), and dialWorkloadGitOps mirrors
// dialWorkload's own ergonomics for GitOpsServiceClient specifically.
// ---------------------------------------------------------------------------

// @peculiar/x509 needs a WebCrypto implementation registered before use.
// Node's own `node:crypto` webcrypto export has TypeScript-incompatible
// (though runtime-compatible) CryptoKey/KeyUsage types against the DOM lib
// @peculiar/x509's type declarations target, so this uses @peculiar/webcrypto
// instead — the same package `spiffe` itself registers internally (see its
// initCryptoProvider) for the identical reason.
const webcrypto = new Crypto();
x509.cryptoProvider.set(webcrypto);

/**
 * Builds a real (self-signed, ECDSA P-256) X509SVID-shaped object for
 * exercising credentialsFromSVID/workloadChannelCredentials against actual
 * ASN.1 DER certificate material. Only the shape a SPIRE agent would hand
 * back over the Workload API matters here (parseCertificateBundle and
 * tls.createSecureContext both do real parsing of these bytes) — this
 * doesn't need to be a certificate any real CA or trust bundle would
 * recognize, since nothing in this suite performs an actual TLS handshake.
 */
async function generateSelfSignedSVID(spiffeId: string): Promise<X509SVID> {
  const keys = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: "CN=signet-workload-test",
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 60_000),
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    keys,
    extensions: [new x509.SubjectAlternativeNameExtension([{ type: "url", value: spiffeId }])],
  });
  const pkcs8 = await webcrypto.subtle.exportKey("pkcs8", keys.privateKey);
  return {
    spiffeId,
    x509Svid: new Uint8Array(cert.rawData),
    x509SvidKey: new Uint8Array(pkcs8),
    bundle: new Uint8Array(cert.rawData),
    hint: "",
  };
}

test("credentialsFromSVID's output (exactly what workloadChannelCredentials resolves to) constructs GitOpsServiceClient, AdminServiceClient, and SecretsServiceClient without connecting", async () => {
  const svid = await generateSelfSignedSVID("spiffe://example.org/ns/default/sa/signet");
  const verify = authorizeTrustDomainMember("example.org");
  const creds = credentialsFromSVID(svid, verify);

  // No live network involved: grpc-js clients are lazy and don't connect
  // until an RPC is actually invoked (mirroring client.test.ts's
  // "constructs a client without connecting" pattern for the bearer-token
  // path). Constructing successfully here is exactly what a caller of
  // workloadChannelCredentials would do to reach GitOpsService/AdminService
  // over this workload's own SPIFFE identity instead of an admin token.
  const gitops = new GitOpsServiceClient("localhost:8443", creds);
  const admin = new AdminServiceClient("localhost:8443", creds);
  const secrets = new SecretsServiceClient("localhost:8443", creds);
  gitops.close();
  admin.close();
  secrets.close();
});

test("workloadChannelCredentials wraps a workload API connection failure with a clear, prefixed message", async () => {
  const originalSocketEnv = process.env.SPIFFE_ENDPOINT_SOCKET;
  delete process.env.SPIFFE_ENDPOINT_SOCKET;
  try {
    // No workloadSocket option and no SPIFFE_ENDPOINT_SOCKET env var: `spiffe`'s
    // createClient throws synchronously before any socket is touched, letting
    // this assert on workloadChannelCredentials's own error-wrapping without
    // opening a connection or needing a real (or fake) Workload API.
    await assert.rejects(
      workloadChannelCredentials({ address: "localhost:8443", trustDomain: "example.org" }),
      /signet: connect to SPIFFE workload API:/,
    );
  } finally {
    if (originalSocketEnv === undefined) {
      delete process.env.SPIFFE_ENDPOINT_SOCKET;
    } else {
      process.env.SPIFFE_ENDPOINT_SOCKET = originalSocketEnv;
    }
  }
});

// ---------------------------------------------------------------------------
// Identity-issuance retry (bytepunx/signet-clients#33)
//
// Ports every case in go-client-admin-plaintext-workload-retry's
// go/client_test.go retry coverage. fakeSleep records the durations
// retryUntilIdentityIssued asks it to wait, without actually blocking, so
// the full-schedule test runs in milliseconds rather than ~15s of real
// waiting.
// ---------------------------------------------------------------------------

/** Shape of the RpcError @protobuf-ts/grpc-transport throws for a gRPC failure. */
function noIdentityIssuedErr(): Error {
  return Object.assign(new Error("no identity issued"), { code: "PERMISSION_DENIED" });
}

function unavailableErr(): Error {
  return Object.assign(new Error("connection refused"), { code: "UNAVAILABLE" });
}

function fakeSleep(): { sleep: (ms: number) => Promise<void>; waited: number[] } {
  const waited: number[] = [];
  return {
    waited,
    sleep: async (ms: number) => {
      waited.push(ms);
    },
  };
}

test("isNoIdentityIssuedErr classifies a PERMISSION_DENIED RpcError-shaped error as true", () => {
  assert.equal(isNoIdentityIssuedErr(noIdentityIssuedErr()), true);
});

test("isNoIdentityIssuedErr classifies a PERMISSION_DENIED error with different text as true", () => {
  assert.equal(
    isNoIdentityIssuedErr(Object.assign(new Error("go away"), { code: "PERMISSION_DENIED" })),
    true,
  );
});

test("isNoIdentityIssuedErr rejects other gRPC status codes", () => {
  assert.equal(isNoIdentityIssuedErr(unavailableErr()), false);
  assert.equal(isNoIdentityIssuedErr(Object.assign(new Error("bad request"), { code: "INVALID_ARGUMENT" })), false);
});

test("isNoIdentityIssuedErr rejects a plain Error with no code field", () => {
  assert.equal(isNoIdentityIssuedErr(new Error("boom")), false);
});

test("isNoIdentityIssuedErr rejects non-object values", () => {
  assert.equal(isNoIdentityIssuedErr(undefined), false);
  assert.equal(isNoIdentityIssuedErr(null), false);
  assert.equal(isNoIdentityIssuedErr("boom"), false);
});

test("retryUntilIdentityIssued succeeds on the first attempt with no sleep", async () => {
  const { sleep, waited } = fakeSleep();
  let calls = 0;
  const probe = async () => {
    calls++;
    return "svid";
  };

  const result = await retryUntilIdentityIssued(probe, sleep);

  assert.equal(result, "svid");
  assert.equal(calls, 1);
  assert.deepEqual(waited, []);
});

test("retryUntilIdentityIssued succeeds after a couple of retries, backing off 1s then 2s", async () => {
  const { sleep, waited } = fakeSleep();
  let calls = 0;
  const probe = async () => {
    calls++;
    if (calls < 3) throw noIdentityIssuedErr();
    return "svid";
  };

  const result = await retryUntilIdentityIssued(probe, sleep);

  assert.equal(result, "svid");
  assert.equal(calls, 3);
  assert.deepEqual(waited, [1000, 2000]);
});

test("retryUntilIdentityIssued exhausts all attempts with the correct backoff schedule (1s/2s/4s/8s)", async () => {
  const { sleep, waited } = fakeSleep();
  let calls = 0;
  const probe = async () => {
    calls++;
    throw noIdentityIssuedErr();
  };

  await assert.rejects(retryUntilIdentityIssued(probe, sleep), /no identity issued after 5 attempts/);
  assert.equal(calls, workloadDialMaxAttempts);
  assert.deepEqual(waited, [...workloadDialBackoffMs]);
});

test("retryUntilIdentityIssued does not retry an unrelated error", async () => {
  const { sleep, waited } = fakeSleep();
  let calls = 0;
  const wantErr = unavailableErr();
  const probe = async () => {
    calls++;
    throw wantErr;
  };

  await assert.rejects(retryUntilIdentityIssued(probe, sleep), (err: unknown) => err === wantErr);
  assert.equal(calls, 1);
  assert.deepEqual(waited, []);
});

// ---------------------------------------------------------------------------
// Event-loop keep-alive during the SVID fetch (bytepunx/signet-clients#47)
//
// The bug only reproduces when *nothing else* keeps the event loop alive --
// exactly the condition a real short-lived script/Job calling dialWorkload
// as one of its first operations is in, and exactly the condition this
// process's own test runner doesn't recreate (the test harness itself keeps
// the loop alive). So this exercises the real mechanism -- a referenced
// timer held across an await backed by an unref'd one, mirroring what
// `spiffe`'s transport actually does and what dialWorkload now guards
// against -- in a real, separately-spawned child process, and asserts on
// that child's actual exit behavior. This can't invoke dialWorkload itself
// without a real SPIRE workload socket; it proves the keep-alive pattern
// dialWorkload now wraps its fetch in, isolated from the SPIFFE/gRPC
// plumbing around it.
// ---------------------------------------------------------------------------

const UNREFFED_WAIT_SCRIPT = `
  const timer = setTimeout(() => { console.log("resolved"); }, 200);
  timer.unref();
`;

const KEPT_ALIVE_SCRIPT = `
  const keepAlive = setInterval(() => {}, 1 << 30);
  const timer = setTimeout(() => {
    console.log("resolved");
    clearInterval(keepAlive);
  }, 200);
  timer.unref();
`;

test("without a keep-alive, a process with only an unref'd timer exits before that timer fires (reproduces the bug's mechanism)", () => {
  const output = execFileSync(process.execPath, ["-e", UNREFFED_WAIT_SCRIPT], { encoding: "utf8" });
  // The process exits as soon as the event loop is otherwise empty -- the
  // unref'd timer never gets a chance to fire, so "resolved" is never
  // logged, and the process exits 0 (a natural, silent drain, not a crash)
  // in well under the timer's own 200ms delay. This is the exact failure
  // shape the issue describes: no error, no rejection, just an early,
  // silent exit.
  assert.equal(output, "");
});

test("holding a referenced keep-alive handle across the wait lets the timer fire before exit (the fix dialWorkload now applies)", () => {
  const output = execFileSync(process.execPath, ["-e", KEPT_ALIVE_SCRIPT], { encoding: "utf8" });
  assert.equal(output.trim(), "resolved");
});
