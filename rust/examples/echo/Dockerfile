# TEST-ONLY IMAGE — DO NOT RUN IN PRODUCTION.
# This container prints retrieved secrets to stdout for smoke-test verification.
# Container logs are commonly captured by log aggregation systems, which would
# leak those secrets outside signet's control entirely.
#
# Part of the bytepunx/signet-smoke-test Docker/Kubernetes harness: one minimal
# "echo" container per client-library language, proving each one actually works
# end-to-end against a real signet + SPIRE deployment (see rust/examples/echo.rs
# for the program this image runs).
#
# Build context is `rust/` (this crate's root), not this directory. Run from
# inside `rust/`:
#
#   docker build -f examples/echo/Dockerfile -t signet-echo-rust:local .
#
# This build is self-contained: an early stage runs `buf generate` itself (see
# the "protogen" stage below) rather than requiring the caller to have already
# run it, so `docker build` alone is sufficient with no local Rust/buf toolchain
# needed. This mirrors this repo's own CI, which always runs `buf generate`
# fresh rather than trusting a committed/cached src/gen (see .github/workflows/ci.yml
# and rust/.gitignore, which excludes src/gen entirely).

# ---------------------------------------------------------------------------
# protogen: regenerate src/gen from the published signet-proto schema, so this
# image build never depends on a local `buf generate` having already been run.
# ---------------------------------------------------------------------------
FROM bufbuild/buf:latest AS protogen

WORKDIR /src
COPY buf.gen.yaml ./
RUN buf generate

# ---------------------------------------------------------------------------
# builder
# ---------------------------------------------------------------------------
# Rust binaries link glibc dynamically by default (unlike Go's static
# binaries), so a distroless/"scratch"-style runtime would need a musl target
# and a fully static build — extra cross-compilation complexity not worth it
# for a first version of a smoke-test fixture. Instead: build and run against
# the *same* Debian base (bookworm) so the runtime's glibc is guaranteed
# compatible with what the binary was linked against, and let the runtime
# stage stay minimal (slim, not distroless) rather than chasing a static musl
# build. Revisit if image size/attack surface ever actually matters here.
FROM rust:1-slim-bookworm AS builder

WORKDIR /src

COPY Cargo.toml ./
COPY src ./src
COPY examples ./examples
COPY --from=protogen /src/src/gen ./src/gen

RUN cargo build --release --example echo --features spiffe-workload

# ---------------------------------------------------------------------------
# runtime
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# ca-certificates: not required for this example's own SPIFFE-mTLS-only
# workload connection (dial_workload authenticates purely via SPIFFE SVIDs,
# not the system trust store), but included for parity with the library's
# other connection path (dial_admin, which does use the system trust store)
# in case this image is ever reused/extended.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --no-create-home --uid 65532 --shell /usr/sbin/nologin echo

COPY --from=builder /src/target/release/examples/echo /usr/local/bin/echo

USER echo:echo

ENTRYPOINT ["/usr/local/bin/echo"]
