# signet-client (Rust)

Rust client for [signet](https://github.com/bytepunx/signet), generated from
[bytepunx/signet-proto](https://github.com/bytepunx/signet-proto) via
[prost](https://github.com/tokio-rs/prost) + [tonic](https://github.com/hyperium/tonic).

**Status:** scaffolded — `buf.gen.yaml` generates prost message types and a tonic async
client into `src/gen`, but the connection-helper wrapper layer (mirroring the Go client in
`../go`) hasn't been written yet.

## Regenerating stubs

```
buf generate
```

Pulls `signet/v1` and `admin/v1` from `buf.build/bytepunx/signet-proto` and regenerates
`src/gen`. Edit the module reference in `buf.gen.yaml` to pin a different schema version.

## Install (once published)

```
cargo add signet-client
```
