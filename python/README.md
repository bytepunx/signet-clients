# signet-client (Python)

Python client for [signet](https://github.com/bytepunx/signet), generated from
[bytepunx/signet-proto](https://github.com/bytepunx/signet-proto).

**Status:** scaffolded — `buf.gen.yaml` is wired up and generates working `grpcio` stubs
into `src/`, but the idiomatic wrapper layer (connection helpers for SPIFFE mTLS /
bearer-token auth, mirroring the Go client in `../go`) hasn't been written yet. Track
progress in the repo's issues.

## Regenerating stubs

```
buf generate
```

Requires the `buf` CLI. Pulls `signet/v1` and `admin/v1` from
`buf.build/bytepunx/signet-proto` and regenerates `src/signet_v1` and `src/admin_v1`
(messages, type stubs, and gRPC service stubs). Edit the module reference in
`buf.gen.yaml` to pin a different schema version.

## Install (once published)

```
pip install signet-client
```
