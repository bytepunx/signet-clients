# signet (Go client)

Go client library for [signet](https://github.com/bytepunx/signet), generated from
[bytepunx/signet-proto](https://github.com/bytepunx/signet-proto) and pinned
independently of the server's own release cycle (see `buf.gen.yaml`).

```
go get github.com/bytepunx/signet-clients/go
```

Go modules need no separate publish step — pushing a `go/vX.Y.Z` tag (which release-please
does automatically) already makes that version resolvable via `go get`.
[`publish-go.yml`](../.github/workflows/publish-go.yml) additionally pings the module proxy
so it's indexed on [pkg.go.dev](https://pkg.go.dev/github.com/bytepunx/signet-clients/go)
immediately rather than on first request.

## Usage

### Workload access (SecretsService, SPIFFE mTLS)

```go
conn, closer, err := signet.DialWorkload(ctx, "signet.internal:8443",
    "unix:///run/spire/sockets/agent.sock", "example.org")
if err != nil {
    log.Fatal(err)
}
defer conn.Close()
defer closer()

client := signet.SecretsClient(conn)
resp, err := client.GetSecret(ctx, &signetv1.GetSecretRequest{
    Namespace: "default",
    Service:   "example",
    Name:      "api-key",
})
```

### Operator access (AdminService/GitOpsService, bearer token)

```go
conn, err := signet.DialAdmin("localhost:8444", token, nil, false)
if err != nil {
    log.Fatal(err)
}
defer conn.Close()

admin := signet.AdminClient(conn)
status, err := admin.Status(ctx, &adminv1.StatusRequest{})
```

See `examples/getsecret` for a complete runnable example.

### Coordinated restarts (no process host, no environment injection)

`WatchBundle`/`AcquireLock`/`WaitForRestart` let a service pull its own configuration
directly and in-memory, and safely coordinate a fleet-wide serialized restart when it
changes — without [kickr](https://github.com/bytepunx/kickr) (a process-host base image
that injects the bundle into a child process's environment) and without ever writing
secrets to the OS environment, where they'd be readable via `/proc/<pid>/environ` by
anything sharing the pod's PID namespace.

This library deliberately does **not**:
- spawn or supervise a child process — it's embedded directly in the process that's
  configuring itself from the bundle;
- write the bundle to environment variables, files, or anywhere outside memory;
- refetch the bundle after the lock is acquired — since there's no replacement process to
  hand it to, the *next* process instance (started fresh by Kubernetes after this one
  exits) fetches it during its own normal startup.

```go
client := signet.SecretsClient(conn)

// Fetch once at startup, configure the app in memory.
bundle, err := client.GetServiceBundle(ctx, &signetv1.GetServiceBundleRequest{
    Namespace: "default", Service: "example",
})

// ... serve traffic ...

// Block until signet reports a change AND this replica holds the restart
// lock (at most one replica restarts at a time, fleet-wide).
lock, err := signet.WaitForRestart(ctx, client, "default", "example",
    30*time.Second /* lock TTL — must cover your graceful shutdown */,
    10*time.Second /* debounce — absorb rapid successive changes */)
if err != nil {
    log.Fatal(err)
}

// Do your own graceful shutdown: drain in-flight requests, close resources.

lock.Release() // release the lock for the next waiting replica
os.Exit(0)      // Kubernetes restarts the pod; the new process fetches fresh config
```

`Lock.Lost()` reports if the lock is lost unexpectedly (stream error, missed heartbeats)
before you call `Release` — treat that as "another replica may now restart concurrently."

See `examples/restart-on-change` for a complete runnable example, and
[signet's restart-lock docs](https://github.com/bytepunx/signet/blob/main/docs/restart-lock.md)
for the underlying protocol.

See also `examples/echo`, a container-oriented, env-var-configured smoke-test fixture (used by
the [signet-smoke-test](https://github.com/bytepunx/signet-smoke-test) harness) that combines
both of the above — it is **test-only** and deliberately prints secrets to stdout.

## Regenerating stubs

```
buf generate
```

Pulls `signet/v1` and `admin/v1` from `buf.build/bytepunx/signet-proto` and regenerates
`gen/`. Edit the module reference in `buf.gen.yaml` to pin a different schema version.
