// Command echo is a minimal smoke-test fixture for the TypeScript/Node
// signet client. It is deployed as a container into a real Kubernetes
// cluster running signet + SPIRE (see bytepunx/signet-smoke-test) to prove
// this client library actually works end-to-end — not just against the
// hand-written fakes the unit test suites use.
//
// The pattern (mirrors ../../README.md's "Coordinated restarts" example and
// ../../../go/examples/restart-on-change/main.go):
//  1. Log a loud "test-only" banner (this program prints decoded secrets to
//     stdout — see the Dockerfile in this directory for why that's only
//     acceptable here).
//  2. dialWorkload to connect via SPIFFE mTLS.
//  3. GetServiceBundle once at startup.
//  4. Print the bundle (secrets base64-decoded) as a single ECHO_BUNDLE:
//     line, so a verification script can grep the container's logs.
//  5. Block on waitForRestart — potentially indefinitely; that's the
//     expected steady state until something changes.
//  6. Once acquired, log an ECHO_RESTART: line, release the lock, and exit
//     0. Kubernetes restarts the pod (restartPolicy: Always); the new
//     instance repeats from step 1 against whatever changed.
//
// Configuration is entirely environment-variable driven (no CLI flags),
// since this runs as a container in Kubernetes:
//   SIGNET_ADDR               - signet workload gRPC address (required)
//   SIGNET_TRUST_DOMAIN       - SPIFFE trust domain (required)
//   SPIFFE_WORKLOAD_SOCKET    - SPIFFE Workload API socket, a "unix://" URI (required)
//   SIGNET_NAMESPACE          - signet namespace to fetch (required; via Downward API)
//   SIGNET_SERVICE            - signet service to fetch (required)
//   RESTART_LOCK_TTL_SECONDS  - restart lock TTL in seconds (optional, default 30)
//   RESTART_DEBOUNCE_SECONDS  - restart debounce in seconds (optional, default 5)
import { dialWorkload, waitForRestart, type SecretsServiceClient } from "@bytepunx/signet-client";

const BANNER = "TEST-ONLY BUILD — DO NOT RUN IN PRODUCTION. This program prints retrieved secrets to stdout.";

interface Config {
  address: string;
  trustDomain: string;
  workloadSocket: string;
  namespace: string;
  service: string;
  lockTtlSeconds: number;
  debounceSeconds: number;
}

/** Reads a required environment variable, failing fast with a specific, named error if it's missing or empty. */
function requireEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.trim() === "") {
    throw new Error(`signet-echo: missing required environment variable ${name}`);
  }
  return value;
}

/** Reads an optional positive-integer environment variable, falling back silently (per spec) if unset or unparseable. */
function optionalPositiveInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return parsed;
}

function loadConfig(): Config {
  return {
    address: requireEnv("SIGNET_ADDR"),
    trustDomain: requireEnv("SIGNET_TRUST_DOMAIN"),
    workloadSocket: requireEnv("SPIFFE_WORKLOAD_SOCKET"),
    namespace: requireEnv("SIGNET_NAMESPACE"),
    service: requireEnv("SIGNET_SERVICE"),
    lockTtlSeconds: optionalPositiveInt("RESTART_LOCK_TTL_SECONDS", 30),
    debounceSeconds: optionalPositiveInt("RESTART_DEBOUNCE_SECONDS", 5),
  };
}

/** Wraps SecretsServiceClient#getServiceBundle's callback API in a Promise — the pattern documented in ../../README.md. */
function getServiceBundle(
  client: SecretsServiceClient,
  namespace: string,
  service: string,
): Promise<{ bundle?: { [key: string]: any }; configVersion: number }> {
  return new Promise((resolve, reject) => {
    client.getServiceBundle({ namespace, service }, (err, resp) => (err ? reject(err) : resolve(resp)));
  });
}

/**
 * Splits a raw GetServiceBundle "bundle" document (config keys at the top
 * level, a reserved "secrets" key mapping name -> base64 plaintext) into a
 * plain object with secrets base64-decoded, so ECHO_BUNDLE's JSON can be
 * parsed directly by a log-based verification script without it also having
 * to know signet's base64 encoding convention.
 */
function decodeBundle(bundle: { [key: string]: any } | undefined): Record<string, unknown> {
  const { secrets, ...config } = bundle ?? {};
  const decodedSecrets: Record<string, string> = {};
  if (secrets && typeof secrets === "object") {
    for (const [name, value] of Object.entries(secrets as Record<string, unknown>)) {
      decodedSecrets[name] = Buffer.from(String(value), "base64").toString("utf8");
    }
  }
  return { ...config, secrets: decodedSecrets };
}

async function main(): Promise<void> {
  // 1. Unconditional banner, logged first: this container's only observable
  // output is its logs, and it prints decoded secrets to them.
  console.log(BANNER);

  const config = loadConfig();

  // 7. Handle SIGTERM/SIGINT gracefully at the blocking point (waitForRestart)
  // instead of hanging until the pod is killed.
  const controller = new AbortController();
  let shutdownSignal: NodeJS.Signals | undefined;
  const shutdown = (signal: NodeJS.Signals) => {
    if (shutdownSignal) return;
    shutdownSignal = signal;
    console.log(`signet-echo: received ${signal}, shutting down`);
    controller.abort(new Error(`received ${signal}`));
  };
  process.once("SIGTERM", () => shutdown("SIGTERM"));
  process.once("SIGINT", () => shutdown("SIGINT"));

  // 2. Connect via SPIFFE mTLS.
  const { client, close } = await dialWorkload({
    address: config.address,
    workloadSocket: config.workloadSocket,
    trustDomain: config.trustDomain,
  });

  try {
    // 3-4. Fetch and print the bundle once at startup, secrets decoded, for
    // log-based verification.
    const bundleResp = await getServiceBundle(client, config.namespace, config.service);
    const decoded = decodeBundle(bundleResp.bundle);
    console.log(`ECHO_BUNDLE: ${JSON.stringify(decoded)}`);

    // 5. Block — potentially indefinitely — until signet reports a change
    // AND this replica holds the fleet-wide restart lock.
    const lock = await waitForRestart(
      client,
      config.namespace,
      config.service,
      config.lockTtlSeconds,
      config.debounceSeconds * 1000,
      { signal: controller.signal },
    );

    // 6. Announce, release, exit 0. Kubernetes restarts the pod
    // (restartPolicy: Always); the new instance repeats from step 1 against
    // whatever changed — that's the behavior this whole harness proves.
    console.log(
      `ECHO_RESTART: acquired restart lock token=${lock.token} expiresAt=${lock.expiresAt?.toISOString() ?? "unknown"}`,
    );
    await lock.release();
    close();
    process.exit(0);
  } catch (err) {
    close();
    if (shutdownSignal) {
      console.log(`signet-echo: exiting after ${shutdownSignal}`);
      process.exit(0);
      return;
    }
    throw err;
  }
}

main().catch((err) => {
  console.error(`signet-echo: fatal: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
