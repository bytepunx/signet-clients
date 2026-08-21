// Tests for the hand-rolled pieces of the SPIFFE workload path: trust-domain
// authorization (mirroring go-spiffe's tlsconfig.AuthorizeMemberOf) and
// DER-to-PEM conversion. These are the two pieces this library had to
// reimplement itself because no maintained Node SPIFFE library provides
// them (see ../README.md). No real certificate material, socket, or SPIRE
// instance is involved — authorizeTrustDomainMember is exercised against
// hand-written fake PeerCertificate-shaped objects.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import type { PeerCertificate } from "node:tls";
import {
  authorizeTrustDomainMember,
  derToPem,
  isNoIdentityIssuedErr,
  retryUntilIdentityIssued,
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
