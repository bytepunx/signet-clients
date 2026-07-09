## signet-clients

Client libraries for [signet](https://github.com/bytepunx/signet), a configuration and
secrets management service. Each language implementation is independent — its own
manifest, its own `buf.gen.yaml` pinned to its own
[bytepunx/signet-proto](https://github.com/bytepunx/signet-proto) schema version, its own
release cadence — so a client can be built against an older or newer schema than whatever
the signet server or any other client currently uses.

| Language   | Path          | Status                                                          |
|------------|---------------|------------------------------------------------------------------|
| Go         | [`go/`](go)             | Implemented — connection helpers for both SPIFFE mTLS (workload) and bearer-token (admin) access |
| Python     | [`python/`](python)         | Scaffolded — codegen wired up, wrapper layer pending |
| TypeScript | [`typescript/`](typescript)     | Scaffolded — codegen wired up, wrapper layer pending |
| Rust       | [`rust/`](rust)           | Scaffolded — codegen wired up, wrapper layer pending |
| C#         | [`csharp/`](csharp)         | Scaffolded — codegen wired up, wrapper layer pending |
| Erlang     | [`erlang/`](erlang)         | Not yet started — no BSR remote plugin for this ecosystem; see its README |

### Why a separate repo per protocol, not per client

The wire protocol lives in `bytepunx/signet-proto`, not here. Every client below declares
it as a dependency and generates its own stubs — nothing here is generated centrally or
committed as a shared artifact. This keeps each client's release cycle, generated-code
layout, and idiomatic wrapper API fully independent of both the server and every other
client.

### Adding a new client

1. Add a directory named for the language/ecosystem.
2. Add a `buf.gen.yaml` with `inputs: - module: buf.build/bytepunx/signet-proto` and the
   plugin(s) appropriate for that language (see existing directories for examples).
3. Run `buf generate` to produce stubs, then add a thin idiomatic connection layer on top
   — see `go/client.go` for the pattern (a SPIFFE-mTLS dial helper for workload access, a
   bearer-token dial helper for admin access; no RPC method wrapping beyond that).
4. Wire up CI (lint/test/build for that language) and a release-please package entry in
   `release-please-config.json`.
