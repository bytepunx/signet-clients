# signet-client (Python)

Python client for [signet](https://github.com/bytepunx/signet), generated from
[bytepunx/signet-proto](https://github.com/bytepunx/signet-proto) and pinned
independently of the server's own release cycle (see `buf.gen.yaml`).

Mirrors the [Go client](../go)'s design: synchronous `grpc` (not `grpc.aio`), with a
background daemon thread doing the blocking read loop for each of the restart-lock
stream and the bundle-watch stream — the same one-goroutine-per-stream shape as the Go
client, translated to Python's concurrency idioms (`threading.Event` instead of
`context.Context`, exceptions instead of `(value, error)` tuples, a context-manager
`Lock`/`Watch` instead of an explicit `Release`/close call only).

## Install

```
pip install signet-client
```

Workload access (`dial_workload`, SPIFFE mTLS) requires an optional extra — see
[SPIFFE support](#spiffe-support) below:

```
pip install signet-client[workload]
```

## Regenerating stubs

```
buf generate
```

Requires the `buf` CLI. Pulls `signet/v1` and `admin/v1` from
`buf.build/bytepunx/signet-proto` and regenerates `src/signet/v1` and `src/admin/v1`
(messages, type stubs, and gRPC service stubs) as PEP 420 namespace packages — no
`__init__.py` needed. Edit the module reference in `buf.gen.yaml` to pin a different
schema version. Generated output is gitignored; both local development and CI run
`buf generate` before building or testing.

## Usage

### Operator access (AdminService/GitOpsService, bearer token)

```python
from signet_client import dial_admin, admin_client
from admin.v1 import admin_pb2 as pb

channel = dial_admin("localhost:8444", token)
try:
    admin = admin_client(channel)
    status = admin.Status(pb.StatusRequest())
finally:
    channel.close()
```

Loopback addresses (`localhost`, `127.0.0.1`, `::1`) default to plaintext (the
documented `kubectl port-forward` workflow); every other address is upgraded to TLS
automatically, using the system trust store unless a CA bundle is passed. Pass
`force_tls=True` to require TLS even for a loopback address, or `ca_pem=read_ca_file(path)`
to pin a specific CA.

Implementation note: the bearer token is injected via a `grpc` client interceptor
rather than `grpc.CallCredentials`. grpc-python's call-credentials machinery refuses to
attach to a plaintext channel (there's no public equivalent of Go's
`PerRPCCredentials.RequireTransportSecurity() == false` escape hatch that lets the Go
client send tokens over the documented plaintext loopback path), so an interceptor —
which works uniformly for both the plaintext and TLS cases — was the more portable
choice here.

### Workload access (SecretsService, SPIFFE mTLS)

```python
from signet_client import dial_workload, secrets_client
from signet.v1 import secrets_pb2 as pb

channel, source = dial_workload("signet.internal:8443",
    "unix:///run/spire/sockets/agent.sock", "example.org")
try:
    client = secrets_client(channel)
    resp = client.GetSecret(pb.GetSecretRequest(
        namespace="default", service="example", name="api-key"))
finally:
    channel.close()
    source.close()  # releases the X509Source's background Workload API connection
```

See `examples/getsecret` for a complete runnable example.

### SPIFFE support

**Status: implemented**, using [`spiffe`](https://pypi.org/project/spiffe/)
(source: [HewlettPackard/py-spiffe](https://github.com/HewlettPackard/py-spiffe)) — the
actively-maintained Python SPIFFE Workload API client. This was verified, not assumed,
while building this module: the package everyone calls "pyspiffe" in conversation is
actually published on PyPI as `spiffe` (`pyspiffe` itself is unclaimed/404), release
history runs through v0.3.0, and the GitHub repo had commits within the week this
client was built. It's a companion, not a fork, of `go-spiffe` — same SPIFFE org
ecosystem, HPE-maintained.

That said, there's a real, deliberate gap versus the Go client:

Go's `DialWorkload` uses `go-spiffe`'s `tlsconfig.AuthorizeMemberOf`, which performs
**two** checks on every connection: (1) the server's certificate chain validates
against the trust bundle, and (2) the server's leaf certificate's SPIFFE ID (from its
URI SAN) is itself a member of the expected trust domain — a callback that runs
*after* the TLS handshake, inspecting the peer certificate directly.

`grpc-python`'s public API (`grpc.secure_channel` / `grpc.ssl_channel_credentials`) has
no hook for check (2) — there is no supported way to inspect the server's peer
certificate post-handshake before the first RPC completes. This client can and does
implement check (1): it fetches the X.509 CA bundle scoped specifically to the
requested trust domain (`X509BundleSet.get_bundle_for_trust_domain`) and uses *only*
that bundle as the channel's root of trust, so any server presenting a chain that
doesn't validate against that trust domain's own CA is rejected at the TLS layer.

In practice, for the common case (one CA hierarchy per trust domain, no federation),
this is equivalent to Go's full `AuthorizeMemberOf` check — a trust domain's CA only
ever signs SVIDs for that trust domain, so chain validation already implies SPIFFE ID
membership. The gap only matters under **federation**, where a single CA might be
trusted by multiple trust domains; in that scenario, this client cannot distinguish "a
member of trust domain A" from "a member of trust domain B, but trusted via a shared
CA" the way Go's client can. If your deployment federates trust domains behind a
shared CA and needs that level of isolation, treat this as a known limitation —
patches implementing a manual post-connection SPIFFE ID check (there are ways to do
this by dropping to `cryptography`-level socket inspection outside of `grpc`'s
abstraction, at the cost of losing `grpc`'s connection pooling/retry machinery) are
welcome.

### Coordinated restarts (no process host, no environment injection)

`watch_bundle`/`acquire_lock`/`wait_for_restart` let a service pull its own
configuration directly and in-memory, and safely coordinate a fleet-wide serialized
restart when it changes — without [kickr](https://github.com/bytepunx/kickr) (a
process-host base image that injects the bundle into a child process's environment)
and without ever writing secrets to the OS environment, where they'd be readable via
`/proc/<pid>/environ` by anything sharing the pod's PID namespace.

This library deliberately does **not**:
- spawn or supervise a child process — it's embedded directly in the process that's
  configuring itself from the bundle;
- write the bundle to environment variables, files, or anywhere outside memory;
- refetch the bundle after the lock is acquired — since there's no replacement process
  to hand it to, the *next* process instance (started fresh by Kubernetes after this
  one exits) fetches it during its own normal startup;
- call `sys.exit()` / `os._exit()` — the caller decides when to actually terminate.

```python
from signet_client import secrets_client, wait_for_restart
from signet.v1 import secrets_pb2 as pb

client = secrets_client(channel)

# Fetch once at startup, configure the app in memory.
bundle = client.GetServiceBundle(pb.GetServiceBundleRequest(
    namespace="default", service="example"))

# ... serve traffic ...

# Block until signet reports a change AND this replica holds the restart
# lock (at most one replica restarts at a time, fleet-wide).
lock = wait_for_restart(client, "default", "example",
    ttl_seconds=30,       # must cover your graceful shutdown
    debounce_seconds=10)  # absorb rapid successive changes

# Do your own graceful shutdown: drain in-flight requests, close resources.

lock.release()  # release the lock for the next waiting replica
sys.exit(0)      # Kubernetes restarts the pod; the new process fetches fresh config
```

`Lock.lost_event` (a `threading.Event`) is set, at most once, if the lock is lost
unexpectedly (stream error, or the server closing the stream) before you call
`release()` — `Lock.lost_error` then holds the triggering exception. Treat this as
"another replica may now restart concurrently."

Heartbeats are sent automatically at **`ttl_seconds / 4`** — signet's documented
convention ("4 consecutive missed heartbeats exhaust the TTL"; see
[signet's restart-lock docs](https://github.com/bytepunx/signet/blob/main/docs/restart-lock.md)).
`ttl_seconds / 2` is a real bug that was previously found and fixed in
[kickr](https://github.com/bytepunx/kickr), signet's existing process-host client — the
`/4` interval is deliberate here, not a typo.

A single background thread owns the lock stream's `recv()` for its entire held
duration — not just fire-and-forget heartbeat sends — so `TTL_EXTENDED` acks update
`Lock.expires_at`, and a stream error or server-initiated close while holding the lock
is detected promptly as lock loss, distinguishable from an intentional `release()`.

See `examples/restart_on_change` for a complete runnable example.

## Testing

```
buf generate
pip install -e ".[dev,workload]"
pytest
```

(`[workload]` is only needed to also exercise `tests/test_workload.py`'s
credential-building path; the rest of the suite has no dependency on it.)

60 test cases, all synchronous and driven against hand-written fakes implementing the
same narrow `LockStream`/`WatchStream` protocols the state machines depend on (see
`tests/fakes.py`) — no live network connection or signet instance anywhere in the
suite. Coverage includes:

- `acquire_lock` rejects `ttl_seconds <= 0` with a clear message, before any stream is
  opened.
- `QUEUE_POSITION` → `ACQUIRED` handoff.
- A stream error before `ACQUIRED` surfaces as a clear `SignetError` (not a hang, not a
  bare exception).
- Heartbeat interval is `ttl_seconds / 4`.
- `TTL_EXTENDED` updates `Lock.expires_at`.
- Lock loss (stream error/close while held) sets `Lock.lost_event` /
  `Lock.lost_error`, distinguishable from an intentional `release()`.
- `release()` is idempotent; the recv/heartbeat threads actually terminate afterwards
  (checked directly, not just inferred).
- `watch_bundle` coalesces rapid successive changes into one pending signal.
- `watch_bundle` reconnects with backoff after a stream error and eventually delivers a
  change; backoff is verified to actually elapse between retries.
- `wait_for_restart`'s debounce coalescing, that it never calls anything resembling
  `GetServiceBundle`, and that it always closes its watch — including when
  `acquire_lock` raises.
- `dial_admin`: empty/whitespace-only token rejected; loopback address defaults to
  plaintext; non-loopback address requires TLS; `force_tls` upgrades a loopback
  address; invalid CA PEM produces a clear parse-error message (both "no certificates
  found" and "certificate block fails to parse" cases), not a generic `grpc`/OpenSSL
  exception; a valid self-signed CA is accepted.
- The `_GrpcLockStream`/`_GrpcWatchStream` adapters that bridge grpc-python's
  request-iterator-based bidi-streaming API to the imperative `send`/`recv`/`close_send`
  protocol above — the one piece of genuinely novel concurrency logic in this port that
  isn't a direct translation of anything in the Go client (Go's generated stub already
  exposes an imperative stream).
- `dial_workload`: a clear, actionable error when the optional `spiffe` extra isn't
  installed; invalid trust domain; Workload API connection failure; no bundle available
  for the requested trust domain (and that the X509Source is still closed on that
  failure path); a full successful dial against a fake SPIFFE source built from a real
  self-signed certificate.

## Known deviations from the Go client

- **SPIFFE post-handshake ID authorization**: see [SPIFFE support](#spiffe-support)
  above — chain validation against a trust-domain-scoped CA bundle is implemented;
  Go's additional post-handshake SPIFFE-ID-SAN check is not, because `grpc-python` has
  no public hook for it.
- **Admin bearer-token transport**: implemented via a `grpc` client interceptor instead
  of `grpc.CallCredentials`, for the reason described above — functionally equivalent
  (the token is injected into every RPC's metadata either way), just a different
  mechanism.
- **No context/deadline threading**: Go's client takes a `context.Context` everywhere,
  so a caller can cancel `AcquireLock`/`WatchBundle`/`WaitForRestart` from outside. This
  client instead exposes `timeout` parameters on the blocking calls that want them
  (`Watch.wait_for_change(timeout=...)`) and a `close()`/`release()` you call yourself;
  there is no built-in "cancel this in-flight acquire from another thread" primitive
  beyond that. This was a deliberate scope cut to keep the surface area idiomatic
  rather than a `context.Context` reimplementation; revisit if a real caller needs it.
