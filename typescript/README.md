# @bytepunx/signet-client (TypeScript / Node)

Node.js gRPC client for [signet](https://github.com/bytepunx/signet), generated from
[bytepunx/signet-proto](https://github.com/bytepunx/signet-proto) via
[ts-proto](https://github.com/stephenh/ts-proto), pinned independently of the server's own
release cycle (see `buf.gen.yaml`).

**Status:** implemented — connection helpers for both bearer-token (admin) access and SPIFFE
mTLS (workload) access, plus in-memory coordinated-restart support (`watchBundle`/
`acquireLock`/`waitForRestart`), mirroring the [Go client](../go). The one real gap is noted
below: there is no SPIFFE library for Node as mature as Go's `go-spiffe`, so `dialWorkload`'s
mTLS credentials are fetched once at dial time rather than rotated automatically in the
background.

```
npm install @bytepunx/signet-client
```

Published to [npm](https://www.npmjs.com/package/@bytepunx/signet-client) automatically by
[`publish-typescript.yml`](../.github/workflows/publish-typescript.yml) whenever
release-please tags a `typescript-v*` release.

## Regenerating stubs

```
buf generate
```

Pulls `signet/v1` and `admin/v1` from `buf.build/bytepunx/signet-proto` and regenerates
`src/gen`, which is committed (matching the [Go client](../go)'s `gen/` — this package now
has real code depending on it, so it's tracked rather than gitignored like the
not-yet-implemented clients). Edit the module reference in `buf.gen.yaml` to pin a
different schema version, then commit the regenerated `src/gen`.

## Usage

### Operator access (AdminService/GitOpsService, bearer token)

```ts
import { dialAdmin } from "@bytepunx/signet-client";

const admin = dialAdmin({ address: "localhost:8444", token });
const status = await new Promise((resolve, reject) =>
  admin.status({}, (err, resp) => (err ? reject(err) : resolve(resp))),
);
admin.close();
```

Loopback addresses (the documented `kubectl port-forward` workflow) use plaintext by
default; every other address is upgraded to TLS automatically using the system trust store,
or the CA in `caPem` if provided. `forceTLS` requests TLS even for a loopback address —
matching the Go client's `DialAdmin` exactly. The bearer token is injected via a grpc-js
*interceptor* rather than composed call credentials: grpc-js's insecure channel credentials
explicitly refuse to compose with call credentials ("Cannot compose insecure credentials"),
which would otherwise break the plaintext-loopback dev workflow that Go's client supports via
`PerRPCCredentials.RequireTransportSecurity() == false`. See `authInterceptor` in
`src/client.ts`.

`plaintext: true` forces insecure transport credentials even for a **non-loopback** address,
bypassing the loopback heuristic entirely (bytepunx/signet-clients#32). This is required once
signet exposes a real in-cluster admin listener (bytepunx/signet#19): dialing that Service by
its cluster-DNS name is a non-loopback address, but the listener is intentionally still
plaintext-behind-bearer-token, not TLS-terminated — without `plaintext`, the loopback
heuristic would pick TLS and the handshake would fail immediately ("wrong version number")
against a server that never speaks TLS on that listener. Per-RPC bearer-token authentication
is unaffected either way. `plaintext` is mutually exclusive with `forceTLS` and with a
non-empty `caPem`; `dialAdmin`/`gitOpsClient`/`adminChannelCredentials` throw if either
combination is requested. Matches the Go client's `DialAdmin` `plaintext` parameter exactly.

```ts
const admin = dialAdmin({ address: "signet-admin.signet.svc.cluster.local:8444", token, plaintext: true });
```

#### Encrypting a secret value for `SyncBundle`/`TriggerSync` (`encryptForSecret`)

signetd never encrypts secrets on a caller's behalf — `SyncBundle`/`TriggerSync` both require
content that is already real [SOPS](https://github.com/getsops/sops) ciphertext (signet's
documented trust model is "only SOPS ciphertext leaves the operator's machine"). `encryptForSecret`
produces that ciphertext client-side: a SOPS-encrypted YAML document holding a single `value` field,
encrypted to one age (X25519) recipient — normally the key returned by
`AdminService.GetSOPSPublicKey` (bytepunx/signet-clients#49).

```ts
import { encryptForSecret, dialAdmin } from "@bytepunx/signet-client";

const admin = dialAdmin({ address: "localhost:8444", token });
const { publicKey } = await new Promise((resolve, reject) =>
  admin.getSopsPublicKey({}, (err, resp) => (err ? reject(err) : resolve(resp))),
);

const content = await encryptForSecret(publicKey, "s3cr3t-api-key");
// `content` is now ready to hand to SyncBundle/TriggerSync as an encrypted secret's contents.
```

This is a from-scratch implementation of the narrow slice of the SOPS envelope format this
package needs, built on [`age-encryption`](https://www.npmjs.com/package/age-encryption) (the
official TypeScript port of age) — no npm package implements the real SOPS format (everything
under "sops" on npm is decrypt-only, or produces an incompatible custom format). Output is
verified to round-trip through the real `sops` binary; see `src/sopsEncrypt.test.ts`.

#### Patching a service's plain config (`GitOpsService.PatchServiceConfig`)

`SyncBundle`'s config path is a full-document replace — pushing a file covering only the
tenant/field you care about silently drops every other entry the live document already has.
`PatchServiceConfig` applies an [RFC 6902](https://www.rfc-editor.org/rfc/rfc6902) JSON Patch
atomically server-side instead, so a caller never needs to read the current document just to
add or remove one entry (bytepunx/signet#38). `jsonPatchAppend`/`jsonPatchAdd`/
`jsonPatchReplace`/`jsonPatchRemove`/`jsonPatchTest` build the `{op, path, from, value}` shape
by hand-writing it out at every call site:

```ts
import { gitOpsClient, jsonPatchAppend } from "@bytepunx/signet-client";

const gitops = gitOpsClient({ address: "signet-admin.signet.svc.cluster.local:8444", token, plaintext: true });

await new Promise((resolve, reject) =>
  gitops.patchServiceConfig(
    {
      namespace: "authstar",
      service: "portcullis",
      operations: [
        // "/-" appends without needing to know the array's current length.
        jsonPatchAppend("/tenants/acme/sessionKeyGenerations", { version: 2, effectiveFrom: new Date().toISOString() }),
      ],
    },
    (err, resp) => (err ? reject(err) : resolve(resp)),
  ),
);
```

Fails `NotFound` if no config document exists yet for `namespace`/`service` — this RPC only
mutates an existing document (use `SyncBundle` or git sync to create the initial one). The whole
patch either fully applies or fails with no partial effect; `jsonPatchTest` is useful as a
concurrency guard (assert an array entry hasn't changed since you last read it, rather than
silently overwriting or removing the wrong one).

### Workload access (SecretsService, SPIFFE mTLS)

```ts
import { dialWorkload } from "@bytepunx/signet-client";

const { client, close } = await dialWorkload({
  address: "signet.internal:8443",
  workloadSocket: "unix:///run/spire/sockets/agent.sock",
  trustDomain: "example.org",
});
try {
  const resp = await new Promise((resolve, reject) =>
    client.getSecret({ namespace: "default", service: "example", name: "api-key" }, (err, r) =>
      err ? reject(err) : resolve(r),
    ),
  );
} finally {
  close();
}
```

`dialWorkload` retries automatically — no opt-in required — if the Workload API reports "no
identity issued" before it can hand back a connection (bytepunx/signet-clients#33). SPIRE's
controller-manager reconciles a brand-new pod's SPIFFE identity registration reactively, off
the pod's own creation event, and that registration takes a few seconds to propagate from
there to the node-local SPIRE agent `dialWorkload` dials over `workloadSocket`. A
freshly-created pod's very first `dialWorkload` call — a Job's is the sharpest case, since a
Job has no prior pod that might have already won this race for the same ServiceAccount — can
lose it outright and see "no identity issued" even though the identity shows up moments
later. This is the same race first hit (and hand-rolled around) in
[bytepunx/kluster](https://github.com/bytepunx/kluster)'s RabbitMQ credential-provisioning
Job; the fix now lives here instead, matching the [Go client](../go)'s `DialWorkload`.

The retry makes up to 5 attempts total — the initial attempt plus up to 4 retries — backing
off 1s, 2s, 4s, 8s between them. Only the "no identity issued" failure (a `PERMISSION_DENIED`
status from the Workload API) is retried: every other error (a bad `workloadSocket`, a
malformed `trustDomain`, a genuine authorization problem once identity issuance is actually
broken rather than merely delayed, ...) is returned to the caller immediately, unretried, so
this never masks a real misconfiguration as a transient blip. See `retryUntilIdentityIssued`
and `isNoIdentityIssuedErr` in `src/workload.ts`.

#### GitOpsService/AdminService over the same workload identity (`workloadChannelCredentials`)

signet's server accepts a workload's own SPIFFE identity — no admin bearer token needed — for
`SyncBundle`, `PatchServiceConfig`, and `GetSOPSPublicKey`, letting a workload self-service its
own bundle/config writes and fetch the active SOPS public key (bytepunx/signet#23, #38, #78).
Cross-namespace/service writes still require an explicit `CreatePolicy` grant from an operator;
every other `GitOpsService`/`AdminService` RPC remains reachable only via the bearer-token path
above.

`dialWorkload` builds its `ChannelCredentials` via `workloadChannelCredentials`, exported
standalone so any other grpc-js client can be bound to the same workload identity:

```ts
import { workloadChannelCredentials, GitOpsServiceClient } from "@bytepunx/signet-client";

const credentials = await workloadChannelCredentials({
  address: "signet.internal:8443",
  workloadSocket: "unix:///run/spire/sockets/agent.sock",
  trustDomain: "example.org",
});
const gitops = new GitOpsServiceClient("signet.internal:8443", credentials);
const resp = await new Promise((resolve, reject) =>
  gitops.getSopsPublicKey({}, (err, r) => (err ? reject(err) : resolve(r))),
);
gitops.close();
```

`dialWorkloadGitOps` wraps that up with the same open/close ergonomics `dialWorkload` provides
for `SecretsServiceClient`:

```ts
import { dialWorkloadGitOps } from "@bytepunx/signet-client";

const { client, close } = await dialWorkloadGitOps({
  address: "signet.internal:8443",
  workloadSocket: "unix:///run/spire/sockets/agent.sock",
  trustDomain: "example.org",
});
const resp = await new Promise((resolve, reject) =>
  client.getSopsPublicKey({}, (err, r) => (err ? reject(err) : resolve(r))),
);
close();
```

See `examples/gitops-workload/` for a runnable, CLI-driven version of the above.

#### The SPIFFE gap (please read before relying on this in production)

Go's client builds on [`go-spiffe`](https://github.com/spiffe/go-spiffe), a mature, official
SPIFFE SDK: `workloadapi.NewX509Source` fetches and **continuously rotates** X.509 SVIDs in
the background, and `tlsconfig.AuthorizeMemberOf` verifies a peer's SPIFFE ID against an
expected trust domain — both battle-tested, both essentially free.

Nothing at that level of maturity exists for Node. We surveyed the npm registry
(`npm search spiffe`, plus manual review) for a maintained SPIFFE Workload API client and
found exactly one real candidate: [`spiffe`](https://www.npmjs.com/package/spiffe)
([`depot/node-spiffe`](https://github.com/depot/node-spiffe) on GitHub). It is thin: 7 GitHub
stars, 9 open issues, and a ~2-year maintenance gap between v0.4.0 (Nov 2023) and v0.5.0 (Jan
2026). It only fetches raw X.509 SVID bytes over the Workload API's gRPC/UDS protocol — it
does not provide certificate rotation, mTLS credential construction, or trust-domain
authorization.

`dialWorkload` uses it anyway, for the one thing it's actually useful for (speaking the
Workload API's UDS/gRPC/protobuf protocol, which would otherwise mean hand-rolling a
non-trivial wire protocol), and this library fills in the two pieces `go-spiffe` normally
provides for free:

**A consequence for the #33 retry above:** go-spiffe exposes two distinct primitives —
`FetchX509Context`, a single-shot, non-watching probe, and `NewX509Source`, a separate
long-lived, internally-self-retrying source — so Go's `DialWorkload` probes readiness with
the former before establishing the real connection via the latter (probing with a
self-retrying source directly would mask the very error the retry needs to classify). `spiffe`
has no long-lived/background-rotating equivalent of `NewX509Source` at all — every
`fetchX509SVID` call is already a single-shot, non-watching fetch, identical in kind to
`FetchX509Context`. So here, unlike Go, there's only one primitive to retry: the probe and the
real fetch are the same operation. `retryUntilIdentityIssued` wraps the SVID fetch directly and
its result becomes the connection's credentials, rather than probing once and re-fetching
through a second, differently-shaped call. The externally observable behavior — 5 attempts,
1s/2s/4s/8s backoff, retrying only "no identity issued" — is unchanged.

- **Credential construction** (`credentialsFromSVID` in `src/workload.ts`): converts the
  fetched DER cert chain, private key, and trust bundle to PEM and builds `@grpc/grpc-js`
  mTLS `ChannelCredentials`.
- **Trust-domain authorization** (`authorizeTrustDomainMember` in `src/workload.ts`): a
  `checkServerIdentity` callback that parses the `URI:spiffe://...` subject alternative name
  off the server's presented leaf certificate and rejects it unless it belongs to the
  expected trust domain — the same policy as `tlsconfig.AuthorizeMemberOf`, reimplemented
  here because nothing off-the-shelf provides it for Node. It's unit tested against
  hand-written fake certificates in `src/workload.test.ts`.

**The real, named gap:** `dialWorkload` fetches the SVID **once**, at dial time. There is no
`X509Source`-equivalent background rotation. A long-lived connection holds onto whatever
certificate was current when you dialed; if your process runs longer than SPIRE's configured
SVID TTL (often on the order of an hour), redial periodically, or simply restart the process
on a schedule (this pairs naturally with `waitForRestart` below) rather than assuming this
connection stays valid indefinitely.

This path has not been exercised against a live SPIRE deployment. Audit it before depending
on it in production. If that's not acceptable for your deployment, two alternatives:

1. Terminate mTLS somewhere better-tested (an Envoy/SPIRE sidecar, for example) and have this
   client talk to that over already-established mTLS or plaintext-over-a-trusted-network.
2. Build your own `ChannelCredentials` however you trust (any Node TLS/SPIFFE tooling you've
   already vetted) and construct the client directly with the exported `secretsClient(address,
   credentials)` — `dialWorkload` is a convenience, not a requirement.

### Coordinated restarts (no process host, no environment injection)

`watchBundle`/`acquireLock`/`waitForRestart` let a service pull its own configuration
directly and in-memory, and safely coordinate a fleet-wide serialized restart when it
changes — without [kickr](https://github.com/bytepunx/kickr) (a process-host base image that
injects the bundle into a child process's environment) and without ever writing secrets to
the OS environment, where they'd be readable via `/proc/<pid>/environ` by anything sharing
the pod's PID namespace.

This library deliberately does **not**:
- spawn or supervise a child process — it's embedded directly in the process that's
  configuring itself from the bundle;
- write the bundle to environment variables, files, or anywhere outside memory;
- refetch the bundle after the lock is acquired — since there's no replacement process to
  hand it to, the *next* process instance (started fresh by Kubernetes after this one exits)
  fetches it during its own normal startup;
- call `process.exit()` anywhere — the caller decides when to actually terminate.

```ts
import { dialWorkload, waitForRestart } from "@bytepunx/signet-client";

const { client } = await dialWorkload({ address: "signet.internal:8443", trustDomain: "example.org" });

// Fetch once at startup, configure the app in memory.
const bundle = await new Promise((resolve, reject) =>
  client.getServiceBundle({ namespace: "default", service: "example" }, (err, r) =>
    err ? reject(err) : resolve(r),
  ),
);

// ... serve traffic ...

// Block until signet reports a change AND this replica holds the restart lock (at most one
// replica restarts at a time, fleet-wide).
const lock = await waitForRestart(
  client,
  "default",
  "example",
  30 /* lock TTL in seconds — must cover your graceful shutdown */,
  10_000 /* debounce in ms — absorb rapid successive changes */,
);

// Do your own graceful shutdown: drain in-flight requests, close resources.

await lock.release(); // release the lock for the next waiting replica
process.exit(0); // Kubernetes restarts the pod; the new process fetches fresh config
```

`lock.lost` is a Promise that resolves with an `Error` if the lock is lost unexpectedly
(stream error, or the server closing the stream) before you call `release()` — never
settling at all after a clean `release()`, so it safely distinguishes loss from an
intentional release even if you attach a handler late. A `'lost'` event is also emitted on
the `Lock` (it's an `EventEmitter`) for consumers who prefer that idiom; both fire from the
same underlying state, at most once.

```ts
lock.lost.then((err) => log.warn("restart lock lost unexpectedly", err));
// or:
lock.on("lost", (err) => log.warn("restart lock lost unexpectedly", err));
```

Heartbeats are sent automatically at `ttlSeconds / 4` — **not** `ttlSeconds / 2` — matching
signet's documented convention that 4 consecutive missed heartbeats exhaust the TTL (see
[signet's restart-lock docs](https://github.com/bytepunx/signet/blob/main/docs/restart-lock.md));
this exact bug (heartbeating at `ttl/2`) was found and fixed in kickr, signet's existing
process-host client, which is why the Go and TypeScript clients both call it out explicitly.

`acquireLock`/`watchBundle`/`waitForRestart` all accept an optional `{ signal }` — a standard
`AbortSignal` — as their cancellation mechanism (the idiomatic Node/web-platform equivalent
of Go's `context.Context`).

See `examples/echo/` for a minimal end-to-end program (env-var configured, built as a
Docker image) used by the [signet-smoke-test](https://github.com/bytepunx/signet-smoke-test)
harness to verify this client against a real signet + SPIRE deployment, and
`examples/gitops-workload/` for a minimal, CLI-flag-configured program demonstrating
`dialWorkloadGitOps`/`workloadChannelCredentials` (see "GitOpsService/AdminService over the
same workload identity" above).

## Testing

```
npm run build && npm test
```

`npm test` runs `node --test dist/**/*.test.js` — Node's built-in test runner, against
compiled output (kept as-is from the original scaffold). 63 test cases across three files,
all driven against hand-written fakes implementing narrow `LockStream`/`WatchStream`
interfaces (mirroring `go/restart_test.go`'s fake-based pattern) — no live network connection
or signet instance is used anywhere:

- **`src/restart.test.ts`** (23 cases) — every case in `go/restart_test.go`, ported: `ttl <=
  0` rejected before opening any stream; `QUEUE_POSITION*` → `ACQUIRED` handoff; a stream
  error before `ACQUIRED` surfaces as a clear rejection; heartbeat interval is
  `ttlSeconds / 4`; `TTL_EXTENDED` updates the tracked expiry; lock loss is detectable and
  distinct from an intentional `release()` (via both the `lost` Promise and the `'lost'`
  event); `release()` is idempotent; `watchBundle` coalesces rapid successive changes into
  one pending signal; `watchBundle` reconnects with backoff after a stream error and
  eventually delivers a change. Plus cases beyond the Go set: a failing (rejecting) `open()`
  is treated the same as a mid-stream error; `AbortSignal` cancellation while waiting to
  acquire a lock, and while watching for changes, is honored promptly rather than hanging.
- **`src/client.test.ts`** (20 cases) — every case in `go/client_test.go`, ported:
  `isLoopbackHost` table; loopback-defaults-to-plaintext / non-loopback-requires-TLS /
  `forceTLS`-forces-TLS-on-loopback; empty/whitespace token rejected with a clear message;
  invalid CA PEM produces a clear parse error, not a raw OpenSSL exception (including a
  syntactically-present-but-malformed PEM block, which Go's suite doesn't separately cover).
  Plus `authInterceptor` coverage specific to this port's design (see the admin-access
  section above for why it exists), and the `plaintext` override coverage for
  bytepunx/signet-clients#32: overrides TLS on a non-loopback address, is a no-op (still
  plaintext) on loopback, leaves existing behavior unchanged when omitted, and is rejected
  when combined with `forceTLS` or `caPem`, at both the `adminTransportMode` and `dialAdmin`
  entry points.
- **`src/workload.test.ts`** (20 cases) — `authorizeTrustDomainMember` (the
  `tlsconfig.AuthorizeMemberOf` reimplementation) against hand-written fake certificates:
  accepts a matching trust domain, rejects a mismatched one, rejects a missing SPIFFE URI
  SAN, normalizes a `spiffe://` prefix, rejects malformed input up front; `derToPem`
  round-trip coverage; the identity-issuance retry coverage for
  bytepunx/signet-clients#33, porting every case in `go/client_test.go`'s retry suite:
  `isNoIdentityIssuedErr` classification (PERMISSION_DENIED in various shapes vs. other
  codes vs. non-RpcError values), `retryUntilIdentityIssued` succeeding immediately with no
  sleep, succeeding after a couple of retries with the right partial backoff, exhausting all
  `workloadDialMaxAttempts` (5) with the full 1s/2s/4s/8s schedule, and passing an unrelated
  error straight through unretried — all via a fake `sleep` injected in place of the default
  `setTimeout`-based one, so the full-schedule case runs in under a millisecond instead of
  ~15s; and, for the GitOps-over-workload-mTLS credential exposure, `workloadChannelCredentials`
  wrapping a synchronous Workload API connection failure with a clear, prefixed error (no
  socket or SPIRE instance needed), plus a real (if minimal) self-signed certificate generated
  via `@peculiar/x509` proving `credentialsFromSVID`'s output — exactly what
  `workloadChannelCredentials` resolves to — constructs `GitOpsServiceClient`,
  `AdminServiceClient`, and `SecretsServiceClient` without connecting.

The two timing-sensitive tests that must observe real elapsed time (the default heartbeat
interval, and one coalescing test) use real timers and take ~200ms–1.3s each; every
reconnect/backoff test overrides `backoffMinMs`/`backoffMaxMs` to keep the suite fast without
weakening what's asserted about the default (1s, doubling, capped at 30s) production
behavior — that shape is exercised structurally, not by waiting out the real default backoff
in every case.
