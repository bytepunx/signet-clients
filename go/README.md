# signet (Go client)

Go client library for [signet](https://github.com/bytepunx/signet), generated from
[bytepunx/signet-proto](https://github.com/bytepunx/signet-proto) and pinned
independently of the server's own release cycle (see `buf.gen.yaml`).

```
go get github.com/bytepunx/signet-clients/go
```

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

## Regenerating stubs

```
buf generate
```

Pulls `signet/v1` and `admin/v1` from `buf.build/bytepunx/signet-proto` and regenerates
`gen/`. Edit the module reference in `buf.gen.yaml` to pin a different schema version.
