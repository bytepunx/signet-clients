# TEST-ONLY IMAGE — DO NOT RUN IN PRODUCTION.
# This container prints retrieved secrets to stdout for smoke-test verification.
# Container logs are commonly captured by log aggregation systems, which would
# leak those secrets outside signet's control entirely.

# syntax=docker/dockerfile:1
#
# Build context is csharp/ (this Dockerfile lives under examples/echo/, two levels down from
# it, so it can COPY the whole SignetClient project tree that EchoExample.csproj references).
# Self-contained: the "proto" stage below runs `buf generate` itself, so there's no
# prerequisite step — just run, from inside csharp/:
#
#   docker build -f examples/echo/Dockerfile -t signet-echo-csharp:local .
#
# (If csharp/gen/ already exists locally from a prior `buf generate`, this still works — the
# proto stage's freshly generated gen/ simply overwrites it in the build stage.)

# ---------------------------------------------------------------------------
# Regenerate gRPC/protobuf stubs from the bytepunx/signet-proto BSR module.
# ---------------------------------------------------------------------------
FROM bufbuild/buf:latest AS proto

WORKDIR /src
COPY buf.gen.yaml ./
RUN buf generate

# ---------------------------------------------------------------------------
# Build the echo example against the main SignetClient project.
# ---------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

WORKDIR /src

# Restore first, separately from the rest of the source, so a source-only change doesn't
# invalidate the NuGet restore layer.
COPY SignetClient.csproj ./
COPY examples/echo/EchoExample.csproj examples/echo/
RUN dotnet restore examples/echo/EchoExample.csproj

# Copy source explicitly (rather than `COPY . .`) so a local `dotnet build`/`buf generate`
# already having been run in this checkout — e.g. because the "before finishing" build/test
# steps in this repo's workflow ran here first — can't leak host-specific bin/obj/gen
# artifacts into the image.
COPY AdminConnection.cs Exceptions.cs Lock.cs Restart.cs Watch.cs WorkloadConnection.cs ./
COPY examples/echo/Program.cs examples/echo/
COPY --from=proto /src/gen ./gen

RUN dotnet publish examples/echo/EchoExample.csproj \
    --configuration Release \
    --no-restore \
    --output /app

# ---------------------------------------------------------------------------
# Runtime image — dotnet/runtime (not aspnet: this is a console app, not a web app).
# ---------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/runtime:8.0 AS final

WORKDIR /app
COPY --from=build --chown=$APP_UID:$APP_UID /app .

# $APP_UID is the non-root "app" user (see mcr.microsoft.com/dotnet/runtime's own
# documentation) baked into the .NET 8 runtime image — no hand-rolled useradd needed.
USER $APP_UID

ENTRYPOINT ["dotnet", "echo.dll"]
