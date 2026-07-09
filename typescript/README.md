# @bytepunx/signet-client (TypeScript / Node)

Node.js gRPC client for [signet](https://github.com/bytepunx/signet), generated from
[bytepunx/signet-proto](https://github.com/bytepunx/signet-proto) via
[ts-proto](https://github.com/stephenh/ts-proto).

**Status:** scaffolded — `buf.gen.yaml` generates idiomatic TypeScript types plus
`@grpc/grpc-js` service clients into `src/gen`, but the connection-helper wrapper layer
(mirroring the Go client in `../go`) hasn't been written yet.

## Regenerating stubs

```
buf generate
```

Pulls `signet/v1` and `admin/v1` from `buf.build/bytepunx/signet-proto` and regenerates
`src/gen`. Edit the module reference in `buf.gen.yaml` to pin a different schema version.

## Install (once published)

```
npm install @bytepunx/signet-client
```
