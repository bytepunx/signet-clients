# TEST-ONLY IMAGE — DO NOT RUN IN PRODUCTION.
# This container prints retrieved secrets to stdout for smoke-test verification.
# Container logs are commonly captured by log aggregation systems, which would
# leak those secrets outside signet's control entirely.
#
# Build context MUST be `go/` (this example imports the rest of the `signet`
# Go module) — not `go/examples/echo/` alone. From inside `go/`:
#   docker build -f examples/echo/Dockerfile -t signet-echo-go:local .

FROM golang:1.26-alpine AS builder

WORKDIR /src

# Cache module downloads separately from source so a code change doesn't
# invalidate the dependency layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/echo \
    ./examples/echo

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/echo /echo

USER nonroot:nonroot

ENTRYPOINT ["/echo"]
