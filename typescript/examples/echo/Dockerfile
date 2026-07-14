# TEST-ONLY IMAGE — DO NOT RUN IN PRODUCTION.
# This container prints retrieved secrets to stdout for smoke-test verification.
# Container logs are commonly captured by log aggregation systems, which would
# leak those secrets outside signet's control entirely.
#
# Build context is `typescript/` (this example imports the library as
# "@bytepunx/signet-client" via Node's self-referencing package imports, so
# the whole package — not just examples/echo/ — must be in the build context).
# Run from inside typescript/:
#
#   docker build -f examples/echo/Dockerfile -t signet-echo-typescript:local .
#
# typescript/src/gen (the buf-generated proto stubs) is committed in this
# repo, unlike the other four language clients, so this build never invokes
# `buf generate` — it compiles directly against what's checked in.

# ---------------------------------------------------------------------------
# Builder: install full deps (incl. devDependencies, for tsc), compile the
# library and this example, then prune devDependencies back out.
# ---------------------------------------------------------------------------
FROM node:22-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src
COPY examples ./examples

# Builds dist/ (the library) and examples/echo/dist/ (this program).
RUN npm run build

# Drop devDependencies (typescript, etc.) — only runtime deps are copied
# into the next stage anyway, but pruning here keeps this layer honest.
RUN npm prune --omit=dev

# ---------------------------------------------------------------------------
# Runtime: production node_modules + compiled output only, non-root.
# ---------------------------------------------------------------------------
FROM node:22-alpine AS runtime

WORKDIR /app

# "type": "module" in package.json is required for Node to treat the
# compiled .js output as ESM.
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/examples/echo/dist ./examples/echo/dist

# node:22-alpine ships a built-in non-root "node" user/group (uid/gid 1000).
USER node

ENTRYPOINT ["node", "examples/echo/dist/index.js"]
