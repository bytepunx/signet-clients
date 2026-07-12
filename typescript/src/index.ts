// Public entry point for @bytepunx/signet-client. See ../README.md for
// usage; the Go client at ../../go documents the design rationale this
// package mirrors.

export {
  SecretsServiceClient,
  AdminServiceClient,
  GitOpsServiceClient,
  secretsClient,
  readCAFile,
  dialAdmin,
  gitOpsClient,
  authInterceptor,
  adminChannelCredentials,
  adminTransportMode,
  isLoopbackHost,
  type DialAdminOptions,
} from "./client.js";

export {
  dialWorkload,
  authorizeTrustDomainMember,
  credentialsFromSVID,
  derToPem,
  type CheckServerIdentityCallback,
  type DialWorkloadOptions,
  type WorkloadConnection,
} from "./workload.js";

export {
  watchBundle,
  BundleWatch,
  runWatchLoop,
  acquireLock,
  acquireLockWithStream,
  Lock,
  waitForRestart,
  lockStreamFromGrpc,
  watchStreamFromGrpc,
  type LockStream,
  type WatchStream,
  type AcquireLockOptions,
  type WatchBundleOptions,
} from "./restart.js";

// Generated proto types/messages, namespaced like the Go client's
// `signetv1`/`adminv1` package aliases to avoid symbol collisions between
// the two schemas (both import shared google.protobuf well-known types).
export * as signetv1 from "./gen/signet/v1/secrets.js";
export * as adminv1 from "./gen/admin/v1/admin.js";
