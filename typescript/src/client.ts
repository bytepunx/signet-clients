// Connection helpers for signet's two listeners, mirroring the Go client's
// client.go:
//   - secretsClient/dialWorkload (see workload.ts) for the workload-facing
//     SecretsService, authenticated via SPIFFE mTLS.
//   - dialAdmin/adminClient/gitOpsClient here for the operator-facing
//     AdminService/GitOpsService, authenticated via a bearer token over TLS
//     (or plaintext for loopback addresses), mirroring signet's own `signet`
//     CLI and kubectl port-forward workflow.
import * as fs from "node:fs";
import * as net from "node:net";
import { X509Certificate } from "node:crypto";
import {
  type ChannelCredentials,
  type ClientOptions,
  credentials as grpcCredentials,
  type Interceptor,
  InterceptingCall,
  RequesterBuilder,
} from "@grpc/grpc-js";
import { AdminServiceClient, GitOpsServiceClient } from "./gen/admin/v1/admin.js";
import { SecretsServiceClient } from "./gen/signet/v1/secrets.js";
import { errMessage } from "./errors.js";

export { SecretsServiceClient, AdminServiceClient, GitOpsServiceClient };

/**
 * secretsClient constructs a SecretsService client bound to a caller-supplied
 * address and channel credentials. This is the escape hatch for workload
 * access when dialWorkload's SPIFFE-mTLS convenience path (see workload.ts)
 * doesn't fit — build ChannelCredentials however you trust and pass them
 * here directly.
 */
export function secretsClient(
  address: string,
  credentials: ChannelCredentials,
  options?: Partial<ClientOptions>,
): SecretsServiceClient {
  return new SecretsServiceClient(address, credentials, options);
}

/** Reads a PEM CA bundle from disk for use with dialAdmin's caPem option. */
export function readCAFile(path: string): Buffer {
  return fs.readFileSync(path);
}

export interface DialAdminOptions {
  /** signet admin listener address, e.g. "localhost:8444" or "signet.internal:8444". */
  address: string;
  /** Bearer token injected as `Authorization: Bearer <token>` on every RPC. */
  token: string;
  /**
   * PEM-encoded CA bundle to trust instead of the system trust store. Also
   * implies TLS even for a loopback address.
   */
  caPem?: Buffer | string;
  /** Force TLS even for a loopback address. */
  forceTLS?: boolean;
  channelOptions?: Partial<ClientOptions>;
}

/**
 * dialAdmin opens a gRPC connection to signet's admin listener, injecting
 * token into every RPC as a bearer credential. Loopback addresses (the
 * documented `kubectl port-forward` workflow) use plaintext by default;
 * every other address is upgraded to TLS automatically using the system
 * trust store, or the CA in caPem if provided. forceTLS requests TLS even
 * for a loopback address.
 */
export function dialAdmin(opts: DialAdminOptions): AdminServiceClient {
  const creds = adminChannelCredentials(opts);
  return new AdminServiceClient(opts.address, creds, mergeAuthInterceptor(opts));
}

/** gitOpsClient dials signet's GitOpsService with the same auth rules as dialAdmin. */
export function gitOpsClient(opts: DialAdminOptions): GitOpsServiceClient {
  const creds = adminChannelCredentials(opts);
  return new GitOpsServiceClient(opts.address, creds, mergeAuthInterceptor(opts));
}

function mergeAuthInterceptor(opts: DialAdminOptions): Partial<ClientOptions> {
  const interceptors: Interceptor[] = [authInterceptor(opts.token.trim()), ...(opts.channelOptions?.interceptors ?? [])];
  return { ...opts.channelOptions, interceptors };
}

/**
 * authInterceptor injects `Authorization: Bearer <token>` into every
 * outgoing call's metadata. This is used instead of grpc-js's
 * `ChannelCredentials.compose(callCredentials)` because grpc-js's insecure
 * channel credentials explicitly refuse to compose with call credentials
 * ("Cannot compose insecure credentials") — a stricter policy than Go's
 * grpc-go, which lets PerRPCCredentials opt out of requiring transport
 * security. An interceptor operates purely at the metadata layer and works
 * identically over plaintext or TLS, which is what the documented
 * plaintext-loopback admin workflow requires.
 */
export function authInterceptor(token: string): Interceptor {
  return (options, nextCall) => {
    const requester = new RequesterBuilder()
      .withStart((metadata, listener, next) => {
        metadata.set("authorization", `Bearer ${token}`);
        next(metadata, listener);
      })
      .build();
    return new InterceptingCall(nextCall(options), requester);
  };
}

/**
 * adminChannelCredentials builds the transport ChannelCredentials for
 * dialAdmin/gitOpsClient: plaintext for a loopback address (unless forceTLS
 * or a CA bundle is supplied), TLS otherwise. Exported standalone so its
 * decision logic — and the invalid-CA-PEM error path — can be unit tested
 * without opening a socket.
 */
export function adminChannelCredentials(opts: DialAdminOptions): ChannelCredentials {
  if (opts.token.trim() === "") {
    throw new Error("signet: token must not be empty");
  }

  const { useTLS } = adminTransportMode(opts.address, opts.caPem, opts.forceTLS ?? false);
  if (!useTLS) {
    return grpcCredentials.createInsecure();
  }

  const caPem = normalizeCAPem(opts.caPem);
  return grpcCredentials.createSsl(caPem);
}

/**
 * adminTransportMode decides whether dialAdmin should use TLS, mirroring the
 * Go client's adminTransportCreds. Split out from adminChannelCredentials so
 * tests can assert the decision (loopback-plaintext / non-loopback-TLS /
 * forceTLS) without needing valid certificate material.
 */
export function adminTransportMode(
  address: string,
  caPem: Buffer | string | undefined,
  forceTLS: boolean,
): { useTLS: boolean } {
  const host = hostOf(address);
  const useTLS = forceTLS || (caPem !== undefined && caPem !== "") || !isLoopbackHost(host);
  return { useTLS };
}

function normalizeCAPem(caPem: Buffer | string | undefined): Buffer | null {
  if (caPem === undefined || caPem === "") {
    return null;
  }
  const buf = Buffer.isBuffer(caPem) ? caPem : Buffer.from(caPem, "utf8");
  const blocks = buf.toString("utf8").match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
  if (!blocks || blocks.length === 0) {
    throw new Error("signet: invalid CA PEM: no PEM certificates found in provided CA bundle");
  }
  for (const block of blocks) {
    try {
      // eslint-disable-next-line no-new
      new X509Certificate(block);
    } catch (err) {
      throw new Error(`signet: invalid CA PEM: ${errMessage(err)}`);
    }
  }
  return buf;
}

/** isLoopbackHost mirrors the Go client's isLoopbackHost. */
export function isLoopbackHost(host: string): boolean {
  if (host === "localhost") return true;
  if (net.isIPv4(host)) return host.startsWith("127.");
  if (host === "::1") return true;
  return false;
}

function hostOf(address: string): string {
  const bracketed = address.match(/^\[(.+)\]:\d+$/);
  if (bracketed) return bracketed[1];

  const lastColon = address.lastIndexOf(":");
  if (lastColon === -1) return address;

  const candidate = address.slice(0, lastColon);
  // A bare (unbracketed) IPv6 host would contain further colons — like Go's
  // net.SplitHostPort, treat that as unparseable and fall back to the whole
  // address as the host, rather than guessing.
  if (candidate.includes(":")) return address;
  return candidate;
}
