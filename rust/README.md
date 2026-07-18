# signet-client (Rust)

Rust client for [signet](https://github.com/bytepunx/signet), generated from
[bytepunx/signet-proto](https://github.com/bytepunx/signet-proto) via
[prost](https://github.com/tokio-rs/prost) + [tonic](https://github.com/hyperium/tonic),
with the same connection-helper and coordinated-restart layer as the
[Go client](../go) — see that package's `client.go`/`restart.go`/`README.md` for the
reference design this crate mirrors (idiomatically, not mechanically).

## Install (once published)

```
cargo add signet-client
```

## Regenerating stubs

```
buf generate
```

Pulls `signet/v1` and `admin/v1` from `buf.build/bytepunx/signet-proto` and regenerates
`src/gen` (gitignored — regenerate locally; CI regenerates fresh too). Edit the module
reference in `buf.gen.yaml` to pin a different schema version.

## Usage

### Operator access (`AdminService`/`GitOpsService`, bearer token)

No optional feature required.

```rust
use signet_client::{admin_client, dial_admin};

let channel = dial_admin("localhost:8444", token, None, false).await?;
let mut admin = admin_client(channel);
let status = admin.status(signet_client::admin::v1::StatusRequest {}).await?;
```

`dial_admin` mirrors the Go client's `DialAdmin` exactly: loopback addresses (the
documented `kubectl port-forward` workflow) default to plaintext; every other address is
upgraded to TLS automatically using the system trust store, or the CA in `ca_pem` if
provided; `force_tls` requests TLS even for a loopback address. An empty/whitespace-only
token is rejected before any connection attempt, and an invalid CA PEM bundle produces a
specific parse error rather than a generic one.

### Workload access (`SecretsService`, SPIFFE mTLS) — `spiffe-workload` feature

```
cargo add signet-client --features spiffe-workload
```

```rust
use signet_client::dial_workload;
use signet_client::signet::v1::secrets_service_client::SecretsServiceClient;

let channel = dial_workload("signet.internal:8443",
    "unix:///run/spire/sockets/agent.sock", "example.org").await?;
let mut client = SecretsServiceClient::new(channel);
let resp = client.get_secret(signet_client::signet::v1::GetSecretRequest {
    namespace: "default".into(), service: "example".into(), name: "api-key".into(),
}).await?;
```

See `examples/getsecret.rs` and `examples/restart_on_change.rs` for complete runnable
examples (`cargo run --example getsecret --features spiffe-workload -- --help`-style
usage is documented in each file's header comment). `examples/echo.rs` (env-var-driven, no
CLI flags) is a container-native smoke-test fixture for the `bytepunx/signet-smoke-test`
Docker/Kubernetes harness — see `examples/echo/Dockerfile` and the header comment in
`echo.rs` for details; **test-only, do not run in production**.

**Status of the SPIFFE integration and a known gap.** Unlike the Erlang client (which has
no maintained protobuf/gRPC toolchain at all for its ecosystem — see `../erlang/README.md`
for that gap), Rust *does* have an actively-maintained SPIFFE Workload API client:
[`spiffe`](https://crates.io/crates/spiffe) (0.16, June 2026, part of the
[rust-spiffe](https://github.com/maxlambrecht/rust-spiffe) project, ~80 releases) plus its
companion [`spiffe-rustls`](https://crates.io/crates/spiffe-rustls) (0.7, June 2026) for
building an mTLS `rustls::ClientConfig` from a live `X509Source`, including a
`trust_domains(...)` authorizer that's the direct equivalent of Go's
`tlsconfig.AuthorizeMemberOf` — this is what `dial_workload` uses. So `dial_workload` is
fully implemented, not a documented gap like Erlang's codegen story. Two smaller,
honestly-stated limitations remain, both discovered while implementing this and neither
blocking (the restart-coordination logic — the more novel/valuable half of this library —
works against any caller-supplied `tonic::transport::Channel`, SPIFFE or not):

- **No live end-to-end verification.** Everything in this crate is tested against
  hand-written fakes with no live network connection (see "Testing" below), by design —
  but that means `dial_workload`'s actual TLS handshake plumbing (the custom
  `tower::Service<Uri>` connector bridging `tokio-rustls` into tonic's `Channel`) has only
  been verified to *compile* and type-check against the real `spiffe`/`spiffe-rustls`/
  `tonic` APIs, not exercised against a real SPIRE agent and signet server. The Go client's
  own test suite has the same gap for its `DialWorkload` (no test exists for it, only for
  `DialAdmin`'s pure functions) — this isn't a regression, just worth stating plainly.
- **No "closer" handle, unlike Go's `DialWorkload`.** Go's version returns
  `(conn, closer, err)` so the caller can explicitly close the `X509Source` (stop its
  background SVID-rotation goroutine) alongside the connection. `spiffe-rustls`'s
  `mtls_client(source: X509Source)` builder takes ownership of the `X509Source` by value
  to back the returned `rustls::ClientConfig`'s live rotation, with no way to hand back a
  shared handle for later shutdown. In practice this just means the background
  SVID-refresh task lives for the life of the process (or until the `Channel` and all its
  clones are dropped) rather than being closable on demand — documented on
  `dial_workload` itself.

If this ever becomes a real problem (e.g. a test harness that dials workload connections
in a loop and needs to bound the number of live `X509Source` background tasks), the fix is
either an upstream API change in `spiffe-rustls` or dropping down to the plain `spiffe`
crate and hand-rolling the `rustls::ClientConfig` (verifier + client-cert resolver)
ourselves, keeping our own `X509Source` handle. Given the restart-coordination primitives
below don't depend on `dial_workload` at all (they take a `Channel` from *any* source), this
wasn't worth the extra complexity for a first implementation.

### Coordinated restarts (no process host, no environment injection)

`watch_bundle`/`acquire_lock`/`wait_for_restart` let a service pull its own configuration
directly and in-memory, and safely coordinate a fleet-wide serialized restart when it
changes — without [kickr](https://github.com/bytepunx/kickr) (a process-host base image
that injects the bundle into a child process's environment) and without ever writing
secrets to the OS environment, where they'd be readable via `/proc/<pid>/environ` by
anything sharing the pod's PID namespace. This mirrors the Go client's `WatchBundle`/
`AcquireLock`/`WaitForRestart` design exactly — see `../go/README.md`'s "Coordinated
restarts" section for the full rationale, which applies unchanged here.

This library deliberately does **not**:
- spawn or supervise a child process — it's embedded directly in the process that's
  configuring itself from the bundle;
- write the bundle to environment variables, files, or anywhere outside memory;
- refetch the bundle after the lock is acquired — since there's no replacement process to
  hand it to, the *next* process instance (started fresh by Kubernetes after this one
  exits) fetches it during its own normal startup;
- call `std::process::exit` (or any equivalent) anywhere — the caller decides when to
  actually terminate the process, after its own graceful shutdown.

```rust
use std::time::Duration;
use signet_client::{wait_for_restart, signet::v1::GetServiceBundleRequest};
use tokio_util::sync::CancellationToken;

// Fetch once at startup, configure the app in memory.
let bundle = client.get_service_bundle(GetServiceBundleRequest {
    namespace: "default".into(), service: "example".into(),
}).await?.into_inner();

// ... serve traffic ...

// Block until signet reports a change AND this replica holds the restart
// lock (at most one replica restarts at a time, fleet-wide).
let lock = wait_for_restart(
    client, "default", "example",
    Duration::from_secs(30), // lock TTL — must cover your graceful shutdown
    Duration::from_secs(10), // debounce — absorb rapid successive changes
    CancellationToken::new(),
).await?;

// Do your own graceful shutdown: drain in-flight requests, close resources.

lock.release().await?; // release the lock for the next waiting replica
std::process::exit(0);  // Kubernetes restarts the pod; the new process fetches fresh config
```

`Lock::lost()` reports if the lock is lost unexpectedly (stream error, missed heartbeats)
before you call `release()` — treat that as "another replica may now restart concurrently."

Heartbeats are sent at `ttl / 4`, not `ttl / 2` — this was a real bug found (and already
fixed) in [kickr](https://github.com/bytepunx/kickr)'s own restart-lock client, and is
called out explicitly in
[signet's restart-lock docs](https://github.com/bytepunx/signet/blob/main/docs/restart-lock.md):
"4 consecutive missed heartbeats exhaust the TTL." A single background task owns the
`AcquireRestartLock` stream for the entire hold duration — reading `TTL_EXTENDED` acks to
keep the tracked expiry current *and* so a stream error or close while holding is
detectable as lock loss, distinguishable from an intentional `release()` — mirroring the
Go client's "a single goroutine/task must continuously read the stream" requirement.

#### A note on `release()`'s idempotence, and other API design choices

`Lock::release()` takes `&self` and is runtime-idempotent (safe to call more than once),
matching Go's design, rather than taking `self` to make double-release a compile error.
See the doc comment on `Lock` in `src/restart.rs` for the full rationale — in short, a
`Lock` is a live network resource coordinated by a background task, not a value naturally
consumed at one call site, and idempotence is more useful than a compile-time guarantee
that would force an `Option<Lock>`/`.take()` dance at every call site.

`acquire_lock` doesn't take a cancellation token the way Go's does (Go needs one because a
goroutine blocks in a synchronous `Recv()` that only a context can interrupt); in Rust, the
"waiting to be acquired" phase runs directly in the caller's own `async fn`, so wrapping the
call in `tokio::time::timeout(...)` (or racing it in a `select!`) cancels it for free. See
the module doc comment at the top of `src/restart.rs` for more on where this crate's design
deliberately diverges from a literal Go-to-Rust port, and why.

## Testing

```
cargo test
```

Every test runs against hand-written fakes (implementing the same internal
`LockStream`/`WatchStream` traits the real `tonic`-backed streams implement) — no live
network connection or signet instance required, mirroring the fake-based pattern in
`../go/restart_test.go`. 24 unit tests plus a doctest cover:

- `acquire_lock` rejects `ttl <= 0` with a specific `RestartError::InvalidTtl`, before ever
  opening a stream (and `validate_ttl`'s whole-second truncation/flooring is tested
  directly).
- `QUEUE_POSITION` → `QUEUE_POSITION` → `ACQUIRED` handoff, and that exactly one request is
  sent before any heartbeat.
- A stream error, and a clean stream close, before `ACQUIRED` both surface as a clear
  `Result::Err` (never a hang or panic) — verified with an explicit `tokio::time::timeout`
  guard.
- Heartbeat interval is `ttl_secs / 4`.
- `TTL_EXTENDED` updates the tracked expiry.
- Lock loss (stream error/close while held) is reported via `Lock::lost()`, and is *not*
  reported after an intentional `release()` — including the "value observed after release
  is deterministically `None`" case, not just "a timeout elapsed" (see the comment on
  `release_does_not_report_lost` in `src/restart.rs` for a real race this test used to have
  and no longer does).
- `release()` is idempotent.
- `watch_bundle`'s reconnect loop coalesces rapid successive changes into a single pending
  signal (bounded `mpsc` channel of capacity 1, filled via non-blocking `try_send`).
- `watch_bundle` reconnects with backoff (1s doubling to a 30s cap) after a stream error and
  eventually delivers a change.
- `dial_admin`/`admin_transport_decision`: empty/whitespace-only token rejected; loopback
  address defaults to plaintext; non-loopback address requires TLS; `force_tls` upgrades a
  loopback address; a CA PEM bundle forces TLS even on loopback; an invalid CA PEM bundle
  produces a specific `ClientError::InvalidCaPem`/`CaPemParse`, not a generic error.

Two tests go beyond the Go suite, surfaced by porting the design into Rust's ownership
model: `lost_is_none_immediately_after_acquire` (a caller polling `Lock::lost()` rather than
awaiting it should see a clean `None`, not block) and
`acquire_lock_stream_closed_before_acquired_is_a_clear_error` (Rust's `Option<T>`-returning
`recv()` makes "stream ended cleanly" a distinct case from "stream errored," both of which
must fail acquisition clearly).

To also build/test the `spiffe-workload` feature (pulls in `spiffe`/`spiffe-rustls`/
`rustls`/`tokio-rustls`):

```
cargo test --features spiffe-workload
cargo build --examples --features spiffe-workload
```
