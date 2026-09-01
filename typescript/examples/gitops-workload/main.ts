// Command gitops-workload demonstrates calling GitOpsService over a
// workload's own SPIFFE mTLS identity instead of an admin bearer token.
//
// dialWorkloadGitOps builds its ChannelCredentials via
// workloadChannelCredentials — the same credential-building step
// dialWorkload uses internally for SecretsServiceClient — so
// GitOpsServiceClient ends up authenticated exactly the same way. This is
// the self-service path signet's server already supports for SyncBundle,
// PatchServiceConfig, and GetSOPSPublicKey (bytepunx/signet#23, #38, #78):
// a workload can push its own bundle, patch its own config, or fetch
// signet's active SOPS public key using nothing but its own workload
// identity, with no admin token in the picture at all. Cross-namespace/
// service writes still require an explicit CreatePolicy grant from an
// operator.
//
// This example calls GetSOPSPublicKey specifically because it needs no
// setup (no bundle to build, no JSON Patch to construct) — SyncBundle and
// PatchServiceConfig are reachable the identical way, just call a different
// method on the same client.
import { parseArgs } from "node:util";
import { adminv1, dialWorkloadGitOps } from "@bytepunx/signet-client";

function usage(): string {
  return [
    "Usage: node dist/main.js [options]",
    "",
    "Options:",
    '  --addr <address>          signet workload gRPC address (default: "localhost:8443")',
    '  --socket <uri>             SPIFFE Workload API socket (default: "unix:///run/spire/sockets/agent.sock")',
    '  --trust-domain <domain>    expected SPIFFE trust domain (default: "example.org")',
  ].join("\n");
}

function parseFlags(argv: string[]): { addr: string; socket: string; trustDomain: string } {
  const { values } = parseArgs({
    args: argv,
    options: {
      addr: { type: "string", default: "localhost:8443" },
      socket: { type: "string", default: "unix:///run/spire/sockets/agent.sock" },
      "trust-domain": { type: "string", default: "example.org" },
      help: { type: "boolean", default: false },
    },
  });
  if (values.help) {
    console.log(usage());
    process.exit(0);
  }
  return { addr: values.addr as string, socket: values.socket as string, trustDomain: values["trust-domain"] as string };
}

async function main(): Promise<void> {
  const { addr, socket, trustDomain } = parseFlags(process.argv.slice(2));

  const { client, close } = await dialWorkloadGitOps({
    address: addr,
    workloadSocket: socket,
    trustDomain,
  });

  try {
    // GitOpsServiceClient bound to workload-mTLS credentials — no separate
    // dial mode or admin token is needed.
    const resp = await new Promise<adminv1.GetSOPSPublicKeyResponse>((resolve, reject) =>
      client.getSopsPublicKey({}, (err, r) => (err ? reject(err) : resolve(r))),
    );
    console.log(`public_key=${resp.publicKey} fingerprint=${resp.fingerprint} environment=${JSON.stringify(resp.environment)}`);
  } finally {
    close();
  }
}

main().catch((err) => {
  console.error(`gitops-workload: fatal: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
