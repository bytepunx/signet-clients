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
harness to verify this client against a real signet + SPIRE deployment.

## Testing

```
npm run build && npm test
```

`npm test` runs `node --test dist/**/*.test.js` — Node's built-in test runner, against
compiled output (kept as-is from the original scaffold). 35 test cases across three files,
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
- **`src/client.test.ts`** (14 cases) — every case in `go/client_test.go`, ported:
  `isLoopbackHost` table; loopback-defaults-to-plaintext / non-loopback-requires-TLS /
  `forceTLS`-forces-TLS-on-loopback; empty/whitespace token rejected with a clear message;
  invalid CA PEM produces a clear parse error, not a raw OpenSSL exception (including a
  syntactically-present-but-malformed PEM block, which Go's suite doesn't separately cover).
  Plus `authInterceptor` coverage specific to this port's design (see the admin-access
  section above for why it exists).
- **`src/workload.test.ts`** (9 cases) — `authorizeTrustDomainMember` (the
  `tlsconfig.AuthorizeMemberOf` reimplementation) against hand-written fake certificates:
  accepts a matching trust domain, rejects a mismatched one, rejects a missing SPIFFE URI
  SAN, normalizes a `spiffe://` prefix, rejects malformed input up front; plus `derToPem`
  round-trip coverage.

The two timing-sensitive tests that must observe real elapsed time (the default heartbeat
interval, and one coalescing test) use real timers and take ~200ms–1.3s each; every
reconnect/backoff test overrides `backoffMinMs`/`backoffMaxMs` to keep the suite fast without
weakening what's asserted about the default (1s, doubling, capped at 30s) production
behavior — that shape is exercised structurally, not by waiting out the real default backoff
in every case.
