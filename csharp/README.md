# Signet.Client (C#)

C# client for [signet](https://github.com/bytepunx/signet), generated from
[bytepunx/signet-proto](https://github.com/bytepunx/signet-proto) and pinned independently of
the server's own release cycle (see `buf.gen.yaml`).

Mirrors the [Go client](../go)'s design: `SignetConnect.DialWorkloadAsync`/`DialAdmin` for
connection setup, and `Restart.WatchBundleAsync`/`AcquireLockAsync`/`WaitForRestartAsync` for
coordinated rolling restarts — expressed idiomatically for .NET (`Task`-based async, specific
exception types, `IAsyncDisposable`), not a mechanical transliteration of the Go syntax.

## Regenerating stubs

```
buf generate
```

Pulls `signet/v1` and `admin/v1` from `buf.build/bytepunx/signet-proto` and regenerates `gen/`
(gitignored — regenerate locally; CI regenerates fresh too). Edit the module reference in
`buf.gen.yaml` to pin a different schema version.

## Building and testing

```
dotnet build      # builds both SignetClient and SignetClient.Tests (via SignetClient.sln)
dotnet test        # runs the full test suite
```

Both commands can also be pointed at a specific project, e.g.
`dotnet test SignetClient.Tests/SignetClient.Tests.csproj`. Requires the .NET 8 SDK; if `dotnet`
isn't already on `PATH`, install it with the official script:

```
curl -sSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh
chmod +x /tmp/dotnet-install.sh
/tmp/dotnet-install.sh --channel 8.0 --install-dir /tmp/dotnet-sdk
export PATH="/tmp/dotnet-sdk:$PATH"
```

Tests use [xUnit](https://xunit.net/) (the modern .NET default — first-class `async Task` test
methods and `Assert.ThrowsAsync` for exception-type assertions, versus MSTest/NUnit's extra
attribute ceremony for async cases). Every test runs against hand-written fakes
(`SignetClient.Tests/Fakes/FakeLockStream.cs`, `FakeWatchStream.cs`) implementing the same
internal `ILockStream`/`IWatchStream` seams the real gRPC-backed implementations use — mirroring
the Go client's fake-stream pattern in `restart_test.go`. None of the ~32 tests open a real
network connection or require a live signet instance.

## Usage

### Workload access (SecretsService, SPIFFE mTLS)

```csharp
await using var conn = await SignetConnect.DialWorkloadAsync(
    "signet.internal:8443", "unix:///run/spire/sockets/agent.sock", "example.org");

var client = conn.SecretsClient;
var resp = await client.GetSecretAsync(new GetSecretRequest
{
    Namespace = "default", Service = "example", Name = "api-key",
});
```

### Operator access (AdminService/GitOpsService, bearer token)

```csharp
using var conn = SignetConnect.DialAdmin("localhost:8444", token);

var admin = conn.AdminClient;
var status = await admin.StatusAsync(new StatusRequest());
```

`DialAdmin` mirrors Go's exact TLS-selection logic: loopback addresses (the documented
`kubectl port-forward` workflow) default to plaintext; every other address is upgraded to TLS
automatically using the system trust store, or a caller-supplied CA bundle; `forceTls: true`
requests TLS even for a loopback address.

### Coordinated restarts (no process host, no environment injection)

`WatchBundleAsync`/`AcquireLockAsync`/`WaitForRestartAsync` let a service pull its own
configuration directly and in-memory, and safely coordinate a fleet-wide serialized restart when
it changes — without [kickr](https://github.com/bytepunx/kickr) (a process-host base image that
injects the bundle into a child process's environment) and without ever writing secrets to the
OS environment, where they'd be readable via `/proc/<pid>/environ` by anything sharing the pod's
PID namespace.

This library deliberately does **not**:
- spawn or supervise a child process — it's embedded directly in the process that's configuring
  itself from the bundle;
- write the bundle to environment variables, files, or anywhere outside memory;
- refetch the bundle after the lock is acquired — since there's no replacement process to hand it
  to, the *next* process instance (started fresh by Kubernetes after this one exits) fetches it
  during its own normal startup;
- call `Environment.Exit` anywhere — the caller decides when to actually terminate the process.

```csharp
var client = conn.SecretsClient;

// Fetch once at startup, configure the app in memory.
var bundle = await client.GetServiceBundleAsync(new GetServiceBundleRequest
{
    Namespace = "default", Service = "example",
});

// ... serve traffic ...

// Block until signet reports a change AND this replica holds the restart lock (at most one
// replica restarts at a time, fleet-wide).
var @lock = await Restart.WaitForRestartAsync(
    client, "default", "example",
    ttl: TimeSpan.FromSeconds(30),      // must cover your graceful shutdown
    debounce: TimeSpan.FromSeconds(10)); // absorb rapid successive changes

// Do your own graceful shutdown: drain in-flight requests, close resources.

await @lock.ReleaseAsync(); // release the lock for the next waiting replica
Environment.Exit(0);         // Kubernetes restarts the pod; the new process fetches fresh config
```

`Lock.Lost` is a `Task<Exception>` that completes, at most once, if the lock is lost unexpectedly
(stream error, missed heartbeats) before you call `ReleaseAsync` — treat completion as "another
replica may now restart concurrently." It deliberately never completes for a clean, intentional
release, so `await Task.WhenAny(lock.Lost, ...)` is a reliable way to distinguish the two.

Heartbeats are sent at `ttl / 4` — not `ttl / 2`. That interval matters: signet's restart-lock
protocol (see
[`docs/restart-lock.md`](https://github.com/bytepunx/signet/blob/main/docs/restart-lock.md))
is explicit that "4 consecutive missed heartbeats exhaust the TTL," and a too-infrequent
heartbeat was a real bug previously found in [kickr](https://github.com/bytepunx/kickr), signet's
existing process-host client.

## SPIFFE support: a maturity gap worth knowing about

`DialWorkloadAsync` is implemented against the third-party
[`Spiffe`](https://www.nuget.org/packages/Spiffe) NuGet package
([vurhanau/csharp-spiffe](https://github.com/vurhanau/csharp-spiffe)) — a C# reimplementation of
[go-spiffe](https://github.com/spiffe/go-spiffe) (the library Go's `DialWorkload` depends on).
Its API maps directly onto go-spiffe's: `X509Source` fetches and rotates an X.509 SVID from the
Workload API, and `Authorizers.AuthorizeMemberOf(trustDomain)` rejects a server whose presented
SPIFFE ID isn't a member of the expected trust domain — the same semantics as Go's
`tlsconfig.AuthorizeMemberOf`.

Unlike go-spiffe, this is **not** an official [spiffe.io](https://spiffe.io) project. As of this
writing it's a single-maintainer repository at a pre-1.0 version (`0.0.3`), with modest adoption
(order of a dozen GitHub stars). It *is* actively maintained — commits and dependency bumps
within the last month — and its design is a faithful, well-structured port of go-spiffe, but
teams adopting `DialWorkloadAsync` should weigh that maturity gap before relying on it in
production, and pin the exact version rather than trusting broad semver ranges. Unlike
[the Erlang client](../erlang), which has no workable path to codegen'd protobuf/gRPC stubs at
all yet, C#'s gap is narrower: only the SPIFFE Workload API integration is on comparatively thin
ice — `DialAdmin`, `WatchBundleAsync`, `AcquireLockAsync`, and `WaitForRestartAsync` have no
SPIFFE dependency whatsoever and work against any `Grpc.Net.Client.GrpcChannel`, including one a
caller constructs by hand (e.g. against a self-managed mTLS setup) without going through
`DialWorkloadAsync` at all.
