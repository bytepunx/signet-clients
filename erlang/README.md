# signet_client (Erlang)

Erlang client for [signet](https://github.com/bytepunx/signet), generated from
[bytepunx/signet-proto](https://github.com/bytepunx/signet-proto).

**Status:** not yet scaffolded. Unlike the other five languages here, there's no
maintained protobuf/gRPC remote plugin for Erlang on the Buf Schema Registry, so this
can't be wired up the same way (a `buf.gen.yaml` pointing at a `remote:` plugin).

The realistic path is a **local** toolchain instead:
- [`gpb`](https://github.com/tomas-abrahamsson/gpb) for protobuf message codegen
  (mature, widely used).
- gRPC service codegen is the harder part — the Erlang gRPC ecosystem
  ([`grpcbox`](https://github.com/tsloughter/grpcbox),
  [`grpc_client`](https://github.com/Bluehouse-Technology/grpc_client)) generally expects
  callers to write the service dispatch by hand against `gpb`-generated messages, rather
  than generating a typed client the way protoc plugins do for Go/Python/etc.

Next step when this language's turn comes up: decide between (a) a `local:` buf.gen.yaml
plugin invocation that shells out to `gpb`'s `protoc-gen-gpb` in CI (requires an Erlang/OTP
toolchain in the build image), or (b) hand-writing the client against `grpcbox` without
buf-driven codegen at all, since the "generate stubs, then wrap" pattern used by the other
five clients doesn't map cleanly onto this ecosystem's tooling.
