// dialWorkload connects to signet's workload-facing SecretsService using
// SPIFFE mTLS, mirroring the Go client's DialWorkload (client.go). See the
// "SPIFFE workload access" section of ../README.md for the honest gap
// writeup: the Node SPIFFE ecosystem has nothing as mature as go-spiffe's
// X509Source, so this hand-rolls the two pieces go-spiffe provides for
// free — PEM credential construction and trust-domain authorization of the
// server's presented identity — on top of a thin, early-stage Workload API
// client (`spiffe` on npm). Read the README before depending on this in
// production.
//
// dialWorkload also retries automatically — no opt-in required — if the
// Workload API reports "no identity issued" before it can hand back a
// connection. See retryUntilIdentityIssued's doc comment and
// bytepunx/signet-clients#33 for the full writeup of the race this closes
// (SPIRE's controller-manager reconciles a brand-new pod's SPIFFE identity
// registration reactively, and propagation to the local agent this dials
// over workloadSocket takes a few seconds — a freshly-created pod/Job's
// very first dial can lose that race outright).
import type { PeerCertificate } from "node:tls";
import { type ChannelCredentials, type ClientOptions, credentials as grpcCredentials } from "@grpc/grpc-js";
import { createClient, parseCertificateBundle, type X509SVID } from "spiffe";
import { SecretsServiceClient } from "./gen/signet/v1/secrets.js";
import { errMessage } from "./errors.js";

/**
 * Matches @grpc/grpc-js's VerifyOptions.checkServerIdentity signature. Not
 * imported directly because grpc-js does not re-export the
 * CheckServerIdentityCallback type name from its package root — only the
 * containing VerifyOptions interface, which structurally accepts this type.
 */
export type CheckServerIdentityCallback = (hostname: string, cert: PeerCertificate) => Error | undefined;

export interface DialWorkloadOptions {
  /** signet workload gRPC address, e.g. "signet.internal:8443". */
  address: string;
  /**
   * SPIFFE Workload API socket, e.g. "unix:///run/spire/sockets/agent.sock".
   * Defaults to the SPIFFE_ENDPOINT_SOCKET environment variable if omitted.
   */
  workloadSocket?: string;
  /**
   * Trust domain the signet server's presented SPIFFE ID must belong to
   * (e.g. "example.org", with or without a "spiffe://" prefix). Connections
   * presenting an identity from any other trust domain are rejected.
   */
  trustDomain: string;
  channelOptions?: Partial<ClientOptions>;
}

export interface WorkloadConnection {
  client: SecretsServiceClient;
  /** Closes the underlying gRPC channel. Idempotent. */
  close(): void;
}

/**
 * dialWorkload fetches a single X.509 SVID and trust bundle from the local
 * SPIFFE Workload API, then constructs a SecretsServiceClient authenticated
 * via mTLS, verifying the server's presented SPIFFE ID is a member of
 * trustDomain (mirroring go-spiffe's tlsconfig.AuthorizeMemberOf).
 *
 * Unlike go-spiffe's X509Source, this fetches credentials once at dial
 * time — there is no background rotation. See the README for why, and for
 * the recommended alternative (supply your own ChannelCredentials to
 * secretsClient()) if that gap matters for your deployment.
 *
 * The fetch itself retries automatically (no opt-in required) if it loses
 * the SPIRE identity-registration-propagation race — see
 * retryUntilIdentityIssued's doc comment.
 */
export async function dialWorkload(opts: DialWorkloadOptions): Promise<WorkloadConnection> {
  const verify = authorizeTrustDomainMember(opts.trustDomain);

  let workloadClient;
  try {
    workloadClient = createClient(opts.workloadSocket);
  } catch (err) {
    throw new Error(`signet: connect to SPIFFE workload API: ${errMessage(err)}`);
  }

  let svid: X509SVID;
  try {
    svid = await retryUntilIdentityIssued(() => fetchFirstX509SVID(workloadClient));
  } catch (err) {
    throw new Error(`signet: fetch X.509 SVID from workload API: ${errMessage(err)}`);
  }

  const creds = credentialsFromSVID(svid, verify);
  const client = new SecretsServiceClient(opts.address, creds, opts.channelOptions);
  return {
    client,
    close: () => client.close(),
  };
}

interface WorkloadApiClient {
  fetchX509SVID(input: Record<string, never>): { responses: AsyncIterable<{ svids: X509SVID[] }> };
}

async function fetchFirstX509SVID(client: WorkloadApiClient): Promise<X509SVID> {
  const call = client.fetchX509SVID({});
  for await (const message of call.responses) {
    if (message.svids.length === 0) {
      throw new Error("workload API response contained no SVIDs");
    }
    return message.svids[0];
  }
  throw new Error("workload API closed the stream without returning an SVID");
}

// ---------------------------------------------------------------------------
// Identity-issuance retry (bytepunx/signet-clients#33)
// ---------------------------------------------------------------------------

/**
 * workloadDialBackoffMs is the wait, in milliseconds, before each retry
 * dialWorkload makes after the Workload API reports "no identity issued"
 * (see retryUntilIdentityIssued's doc comment): 1s, 2s, 4s, 8s —
 * exponential, doubling each time and capped at 8s. This is the exact
 * schedule verified working in a real downstream consumer that hit this
 * race (bytepunx/signet-clients#33 — bytepunx/kluster's RabbitMQ
 * credential-provisioning Job, which retries its own dial 5 times total
 * with this identical backoff, and the Go client's workloadDialBackoff),
 * so workloadDialBackoffMs.length retries are made beyond the initial
 * attempt — workloadDialMaxAttempts total — with a worst case of roughly
 * 15s of waiting before dialWorkload gives up.
 */
export const workloadDialBackoffMs: readonly number[] = [1000, 2000, 4000, 8000];

/**
 * workloadDialMaxAttempts is the total number of identity-readiness probes
 * dialWorkload makes (the initial attempt plus workloadDialBackoffMs.length
 * retries) before giving up.
 */
export const workloadDialMaxAttempts = workloadDialBackoffMs.length + 1;

/**
 * Default sleep implementation used by retryUntilIdentityIssued between
 * retries. Exposed as a parameter (not hardcoded) purely so tests can
 * inject a fake that resolves instantly instead of waiting out the real
 * schedule — mirroring the Go client's retryUntilIdentityIssued, which
 * takes an injectable `sleep func(context.Context, time.Duration) bool`
 * for the identical reason.
 */
function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    timer.unref?.();
  });
}

/**
 * isNoIdentityIssuedErr reports whether err is the SPIFFE Workload API's
 * "no identity issued" failure: a PermissionDenied status returned by
 * FetchX509SVID when the calling workload has no SPIFFE identity
 * registered yet — the exact condition retryUntilIdentityIssued's retry
 * exists for. `spiffe` (this client's Workload API library) builds on
 * @protobuf-ts/grpc-transport, which surfaces gRPC failures as an
 * `RpcError` whose `code` field is the string form of @grpc/grpc-js's
 * status enum (e.g. "PERMISSION_DENIED" for codes.PermissionDenied) — this
 * checks that field structurally rather than importing RpcError from
 * @protobuf-ts/runtime-rpc, which is a transitive dependency of `spiffe`,
 * not a direct dependency of this package. Matching is deliberately on
 * status code alone, not error text, since the code is the stable part of
 * this contract across SPIRE versions — mirroring the Go client's
 * isNoIdentityIssuedErr, which matches on codes.PermissionDenied alone for
 * the same reason.
 */
export function isNoIdentityIssuedErr(err: unknown): boolean {
  return typeof err === "object" && err !== null && "code" in err && (err as { code: unknown }).code === "PERMISSION_DENIED";
}

/**
 * retryUntilIdentityIssued calls probe, retrying per workloadDialBackoffMs
 * (via sleep, so tests can substitute a non-blocking fake) as long as probe
 * keeps failing with isNoIdentityIssuedErr. It resolves with probe's result
 * as soon as probe succeeds, rejects with the first error probe returns
 * that isn't a "no identity issued" failure, or rejects with a wrapped
 * error naming the last "no identity issued" failure once
 * workloadDialMaxAttempts is exhausted.
 *
 * This mirrors the Go client's retryUntilIdentityIssued/DialWorkload, with
 * one deliberate shape difference forced by what `spiffe` (this client's
 * Workload API library) actually exposes: go-spiffe provides two distinct
 * primitives — a single-shot, non-watching `FetchX509Context` used only to
 * probe readiness, and a separate long-lived, internally-self-retrying
 * `NewX509Source` used for the real connection once identity is confirmed
 * issued (probing with the latter directly would mask the very error this
 * retry needs to classify, since it already retries "no identity issued"
 * forever on its own with an uncontrollable, unbounded backoff). `spiffe`
 * has no long-lived/background-rotating equivalent of NewX509Source at all
 * (see the README's SPIFFE gap writeup) — every call to fetchX509SVID is
 * already a single-shot, non-watching fetch, identical in kind to
 * FetchX509Context. So here, unlike Go, the probe and the real fetch are
 * the same operation: retryUntilIdentityIssued wraps fetchFirstX509SVID
 * directly and its resolved value becomes the SVID dialWorkload uses,
 * rather than probing once and then re-fetching through a second,
 * differently-shaped call. The externally observable behavior is
 * unchanged: up to workloadDialMaxAttempts (5) attempts, backing off per
 * workloadDialBackoffMs (1s, 2s, 4s, 8s), retrying only "no identity
 * issued" and passing every other error straight through unretried.
 */
export async function retryUntilIdentityIssued<T>(
  probe: () => Promise<T>,
  sleep: (ms: number) => Promise<void> = defaultSleep,
): Promise<T> {
  let lastErr: unknown;
  for (let attempt = 0; attempt < workloadDialMaxAttempts; attempt++) {
    try {
      return await probe();
    } catch (err) {
      lastErr = err;
      if (!isNoIdentityIssuedErr(err)) {
        throw err;
      }
      if (attempt === workloadDialBackoffMs.length) {
        break;
      }
      await sleep(workloadDialBackoffMs[attempt]);
    }
  }
  throw new Error(`no identity issued after ${workloadDialMaxAttempts} attempts: ${errMessage(lastErr)}`);
}

/** Builds grpc-js mTLS ChannelCredentials from a fetched X509SVID. */
export function credentialsFromSVID(svid: X509SVID, checkServerIdentity: CheckServerIdentityCallback): ChannelCredentials {
  const certChainPem = Buffer.from(parseCertificateBundle(svid.x509Svid).toString("pem-chain"));
  const trustBundlePem = Buffer.from(parseCertificateBundle(svid.bundle).toString("pem-chain"));
  const keyPem = Buffer.from(derToPem(svid.x509SvidKey, "PRIVATE KEY"));
  return grpcCredentials.createSsl(trustBundlePem, keyPem, certChainPem, { checkServerIdentity });
}

/** Converts a DER-encoded blob into PEM text with the given block label. */
export function derToPem(der: Uint8Array, label: string): string {
  const base64 = Buffer.from(der).toString("base64");
  const lines: string[] = [];
  for (let i = 0; i < base64.length; i += 64) {
    lines.push(base64.slice(i, i + 64));
  }
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

/**
 * authorizeTrustDomainMember returns a grpc-js checkServerIdentity callback
 * that accepts a peer certificate only if it presents a SPIFFE ID (a
 * "URI:spiffe://..." subject alternative name) belonging to trustDomain.
 * This is the same policy as go-spiffe's tlsconfig.AuthorizeMemberOf,
 * reimplemented here because no maintained Node SPIFFE library provides it
 * (see the README's SPIFFE gap writeup).
 */
export function authorizeTrustDomainMember(trustDomain: string): CheckServerIdentityCallback {
  const expected = normalizeTrustDomain(trustDomain);
  return (_hostname: string, cert: PeerCertificate): Error | undefined => {
    const spiffeId = extractSpiffeId(cert);
    if (!spiffeId) {
      return new Error(
        `signet: server did not present a SPIFFE ID (no "URI:spiffe://" subject alternative name found); expected trust domain "${expected}"`,
      );
    }
    const presented = trustDomainOf(spiffeId);
    if (presented !== expected) {
      return new Error(
        `signet: server SPIFFE ID "${spiffeId}" belongs to trust domain "${presented}", not the expected trust domain "${expected}"`,
      );
    }
    return undefined;
  };
}

function extractSpiffeId(cert: PeerCertificate): string | undefined {
  const san = cert.subjectaltname;
  if (!san) return undefined;
  for (const part of san.split(/,\s*/)) {
    if (part.startsWith("URI:spiffe://")) {
      return part.slice("URI:".length);
    }
  }
  return undefined;
}

function trustDomainOf(spiffeId: string): string {
  const withoutScheme = spiffeId.slice("spiffe://".length);
  const slashIdx = withoutScheme.indexOf("/");
  return slashIdx === -1 ? withoutScheme : withoutScheme.slice(0, slashIdx);
}

function normalizeTrustDomain(trustDomain: string): string {
  const trimmed = trustDomain.trim();
  if (trimmed === "") {
    throw new Error("signet: trust domain must not be empty");
  }
  const withoutScheme = trimmed.startsWith("spiffe://") ? trimmed.slice("spiffe://".length) : trimmed;
  if (withoutScheme.includes("/")) {
    throw new Error(`signet: invalid trust domain "${trustDomain}": must not contain a path`);
  }
  return withoutScheme;
}
