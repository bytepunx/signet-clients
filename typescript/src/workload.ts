// dialWorkload connects to signet's workload-facing SecretsService using
// SPIFFE mTLS, mirroring the Go client's DialWorkload (client.go). See the
// "SPIFFE workload access" section of ../README.md for the honest gap
// writeup: the Node SPIFFE ecosystem has nothing as mature as go-spiffe's
// X509Source, so this hand-rolls the two pieces go-spiffe provides for
// free — PEM credential construction and trust-domain authorization of the
// server's presented identity — on top of a thin, early-stage Workload API
// client (`spiffe` on npm). Read the README before depending on this in
// production.
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
    svid = await fetchFirstX509SVID(workloadClient);
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
