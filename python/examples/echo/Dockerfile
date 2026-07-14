# TEST-ONLY IMAGE — DO NOT RUN IN PRODUCTION.
# This container prints retrieved secrets to stdout for smoke-test verification.
# Container logs are commonly captured by log aggregation systems, which would
# leak those secrets outside signet's control entirely.
#
# Build (from inside python/ — the build context needs the rest of the
# signet_client package, not just this example directory):
#
#   docker build -f examples/echo/Dockerfile -t signet-echo-python:local .
#
# Self-contained on purpose: `buf` is not guaranteed to be installed wherever
# this image eventually gets built in CI, so the "proto" stage below sources
# the `buf` CLI binary straight from the official bufbuild/buf image (pinned
# to the same 1.71.0 used when this Dockerfile was authored — bump alongside
# buf.gen.yaml's schema pin) and runs `buf generate` itself. No pre-generated
# src/signet or src/admin is required on the host; this build does require
# network access to buf.build to pull the bytepunx/signet-proto module and
# its remote codegen plugins (protocolbuffers/python, protocolbuffers/pyi,
# grpc/python), the same way this repo's CI does (see .github/workflows/ci.yml).

# --- source of the buf CLI binary only; nothing else from this stage is used
FROM bufbuild/buf:1.71.0 AS buf

# --- stage 1: buf generate -> src/signet, src/admin -----------------------
FROM python:3.12-slim AS proto
COPY --from=buf /usr/local/bin/buf /usr/local/bin/buf
WORKDIR /src
COPY buf.gen.yaml ./
RUN buf generate

# --- stage 2: install signet-client[workload] + generated stubs into a venv
FROM python:3.12-slim AS builder
WORKDIR /src
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"
COPY pyproject.toml README.md ./
COPY src ./src
COPY --from=proto /src/src/signet ./src/signet
COPY --from=proto /src/src/admin ./src/admin
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir ".[workload]"

# --- stage 3: runtime — just the venv + this script, non-root -------------
FROM python:3.12-slim AS runtime

RUN useradd --system --no-create-home --shell /usr/sbin/nologin echo

COPY --from=builder /opt/venv /opt/venv
COPY examples/echo/main.py /app/main.py

ENV PATH="/opt/venv/bin:${PATH}"
WORKDIR /app
USER echo

ENTRYPOINT ["python", "/app/main.py"]
