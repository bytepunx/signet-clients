//! Rust client for [signet](https://github.com/bytepunx/signet).
//!
//! Two connection modes mirror the two listeners signet exposes:
//!   - [`dial_workload`](client::dial_workload) connects to the workload-facing
//!     `SecretsService` using SPIFFE mTLS, the same credential mechanism the
//!     signet server itself uses to authenticate callers. Gated behind the
//!     `spiffe-workload` feature — see the crate README for why, and for the
//!     fallback path (bring your own `tonic::transport::Channel`) when it's
//!     disabled.
//!   - [`dial_admin`](client::dial_admin) connects to the operator-facing
//!     `AdminService`/`GitOpsService` using a bearer token over TLS (or
//!     plaintext for loopback addresses), mirroring signet's own `signet`
//!     CLI.
//!
//! [`watch_bundle`](restart::watch_bundle), [`acquire_lock`](restart::acquire_lock),
//! and [`wait_for_restart`](restart::wait_for_restart) implement signet's
//! coordinated-restart protocol: a service can watch for its own bundle
//! changes and safely serialize a fleet-wide restart via signet's distributed
//! restart lock, without a process host and without ever writing secrets to
//! the environment or disk. See `README.md`'s "Coordinated restarts" section
//! for the full design rationale, mirrored from the Go client.

pub mod client;
pub mod restart;

/// Generated protobuf/tonic bindings for signet, from bytepunx/signet-proto.
/// Run `buf generate` to regenerate `src/gen`.
// Each base file ends with its own `include!` of the matching *.tonic.rs
// file, so only the base file needs including here.
pub mod signet {
    pub mod v1 {
        include!("gen/signet/v1/signet.v1.rs");
    }
}

pub mod admin {
    pub mod v1 {
        include!("gen/admin/v1/admin.v1.rs");
    }
}

pub use client::{
    admin_client, dial_admin, gitops_client, read_ca_file, AdminChannel, ClientError,
    TokenInterceptor,
};
#[cfg(feature = "spiffe-workload")]
pub use client::dial_workload;
pub use restart::{acquire_lock, wait_for_restart, watch_bundle, Lock, RestartError};
