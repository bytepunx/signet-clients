//! Demonstrates calling `GitOpsService` over a workload's own SPIFFE mTLS
//! identity instead of an admin bearer token. Mirrors
//! `go/examples/gitops-workload`.
//!
//! `dial_workload` returns a plain `tonic::transport::Channel` — the same
//! one `SecretsServiceClient` binds to in `examples/getsecret.rs` — so
//! `gitops_client(channel)` works exactly the same way. This is the
//! self-service path signet's server already supports for `SyncBundle`,
//! `PatchServiceConfig`, and `GetSOPSPublicKey` (bytepunx/signet#23, #38,
//! #78): a workload can push its own bundle, patch its own config, or fetch
//! signet's active SOPS public key using nothing but its own workload
//! identity, with no admin token in the picture at all.
//! Cross-namespace/service writes still require an explicit `CreatePolicy`
//! grant from an operator — see the design doc's "Self-service workload
//! pushes" section.
//!
//! This example calls `GetSOPSPublicKey` specifically because it needs no
//! setup (no bundle to build, no JSON Patch to construct) — `SyncBundle` and
//! `PatchServiceConfig` are reachable the identical way, just swap the
//! client method called below.
//!
//! Requires the `spiffe-workload` feature:
//!
//! ```text
//! cargo run --example gitops_workload --features spiffe-workload -- \
//!     --addr localhost:8443 \
//!     --socket unix:///run/spire/sockets/agent.sock \
//!     --trust-domain example.org
//! ```

use std::time::Duration;

use signet_client::admin::v1::GetSopsPublicKeyRequest;
use signet_client::{dial_workload, gitops_client};

struct Args {
    addr: String,
    socket: String,
    trust_domain: String,
}

fn parse_args() -> Args {
    let mut args = Args {
        addr: "localhost:8443".to_string(),
        socket: "unix:///run/spire/sockets/agent.sock".to_string(),
        trust_domain: "example.org".to_string(),
    };

    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().expect("missing value for flag");
        match flag.as_str() {
            "--addr" => args.addr = value(),
            "--socket" => args.socket = value(),
            "--trust-domain" => args.trust_domain = value(),
            other => panic!("unknown flag {other}"),
        }
    }
    args
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();

    let channel = tokio::time::timeout(
        Duration::from_secs(10),
        dial_workload(&args.addr, &args.socket, &args.trust_domain),
    )
    .await??;

    // gitops_client accepts any tonic service satisfying the generated
    // client's bound, including the plain Channel dial_workload returns —
    // no separate dial mode is needed.
    let mut client = gitops_client(channel);
    let resp = client
        .get_sops_public_key(GetSopsPublicKeyRequest {})
        .await?
        .into_inner();

    println!(
        "public_key={} fingerprint={} environment={:?}",
        resp.public_key, resp.fingerprint, resp.environment
    );
    Ok(())
}
