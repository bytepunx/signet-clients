## signet-clients

Client libraries for [signet](https://github.com/bytepunx/signet), a configuration and
secrets management service. Each language implementation is independent — its own
manifest, its own `buf.gen.yaml` pinned to its own
[bytepunx/signet-proto](https://github.com/bytepunx/signet-proto) schema version, its own
release cadence — so a client can be built against an older or newer schema than whatever
the signet server or any other client currently uses.

| Language   | Path          | Package                                                                                       | Status                                                          |
|------------|---------------|------------------------------------------------------------------------------------------------|--------------------------------------------------------------------|
| Go         | [`go/`](go)             | `go get github.com/bytepunx/signet-clients/go` — no registry, resolved directly from git tags | Implemented — connection helpers for both SPIFFE mTLS (workload) and bearer-token (admin) access, plus in-memory coordinated-restart support (`WatchBundle`/`AcquireLock`/`WaitForRestart`) |
| Rust       | [`rust/`](rust)           | [crates.io/crates/signet-client](https://crates.io/crates/signet-client)                       | Implemented — same shape as Go. SPIFFE support is on equal footing (`rust-spiffe` is mature and well-maintained) |
| Python     | [`python/`](python)         | [pypi.org/project/signet-client](https://pypi.org/project/signet-client/)                      | Implemented, **except SPIFFE workload mTLS does not work at all** — `grpc-python` has no public API to validate a server certificate that carries only a SPIFFE URI SAN, so `dial_workload` cannot connect to a real signet instance. Confirmed live, not just theorized. Admin/bearer-token access (`dial_admin`) is unaffected. See `python/README.md` and [#14](https://github.com/bytepunx/signet-clients/issues/14) for tracking |
| TypeScript | [`typescript/`](typescript)     | [npmjs.com/package/@bytepunx/signet-client](https://www.npmjs.com/package/@bytepunx/signet-client) | Implemented — same shape as Go. SPIFFE support is real but thin (no background SVID rotation — see `typescript/README.md`) |
| C#         | [`csharp/`](csharp)         | [nuget.org/packages/Signet.Client](https://www.nuget.org/packages/Signet.Client)               | Implemented — same shape as Go. SPIFFE support depends on a single-maintainer, pre-1.0 library (see `csharp/README.md`) |
| Erlang     | [`erlang/`](erlang)         | —                                                                                               | Not yet started — no BSR remote plugin for this ecosystem; see its README |

Each language publishes automatically when release-please tags a release (see
`.github/workflows/publish-*.yml`) — merging a release-please PR is the only manual step.

### Why a separate repo per protocol, not per client

The wire protocol lives in `bytepunx/signet-proto`, not here. Every client below declares
it as a dependency and generates its own stubs — nothing here is generated centrally or
committed as a shared artifact. This keeps each client's release cycle, generated-code
layout, and idiomatic wrapper API fully independent of both the server and every other
client.

### Development setup

```
git config core.hooksPath .githooks
```

Enables a pre-commit hook that regenerates Go's and TypeScript's proto stubs (the two
languages with a committed `gen/`/`src/gen/` directory CI enforces) and blocks the commit
if that output doesn't match what's staged — the same check
[`ci.yml`](.github/workflows/ci.yml) runs, just before you push instead of after. Requires
`buf` on `PATH`; the hook prints a warning and no-ops if it's missing rather than blocking
every commit for contributors who haven't installed it yet, but CI still enforces the
check either way. Skip once with `git commit --no-verify` if you need to.

### Adding a new client

1. Add a directory named for the language/ecosystem.
2. Add a `buf.gen.yaml` with `inputs: - module: buf.build/bytepunx/signet-proto` and the
   plugin(s) appropriate for that language (see existing directories for examples).
3. Run `buf generate` to produce stubs, then add a thin idiomatic connection layer on top
   — see `go/client.go` (or any of the other four implemented clients) for the pattern (a
   SPIFFE-mTLS dial helper for workload access, a bearer-token dial helper for admin
   access; no RPC method wrapping beyond that) and `go/restart.go` for the
   coordinated-restart pattern (watch for changes, acquire the distributed restart lock,
   let the caller decide when to exit). Research whether a maintained SPIFFE Workload API
   client exists for the new language before assuming one does or doesn't — the answer has
   varied a lot across the five languages implemented so far, from "as mature as Go's" to
   "no viable option at all." Document whatever gap you find honestly, the way each
   existing client's README does, rather than silently skipping workload support.
4. Wire up CI (lint/test/build for that language) and a release-please package entry in
   `release-please-config.json`.
