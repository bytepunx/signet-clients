# Signet.Client (C#)

C# client for [signet](https://github.com/bytepunx/signet), generated from
[bytepunx/signet-proto](https://github.com/bytepunx/signet-proto).

**Status:** scaffolded — `buf.gen.yaml` generates `Grpc.Net.Client`-compatible stubs into
`gen/`, but the connection-helper wrapper layer (mirroring the Go client in `../go`)
hasn't been written yet.

## Regenerating stubs

```
buf generate
```

Pulls `signet/v1` and `admin/v1` from `buf.build/bytepunx/signet-proto` and regenerates
`gen/`. Edit the module reference in `buf.gen.yaml` to pin a different schema version.

## Install (once published)

```
dotnet add package Signet.Client
```
