//! Minimal example of using the signet Rust client to fetch a secret over
//! SPIFFE mTLS. Mirrors `go/examples/getsecret`.
//!
//! Requires the `spiffe-workload` feature:
//!
//! ```text
//! cargo run --example getsecret --features spiffe-workload -- \
//!     --addr localhost:8443 \
//!     --socket unix:///run/spire/sockets/agent.sock \
//!     --trust-domain example.org \
//!     --namespace default --service example --name api-key
//! ```

use std::time::Duration;

use signet_client::dial_workload;
use signet_client::signet::v1::secrets_service_client::SecretsServiceClient;
use signet_client::signet::v1::GetSecretRequest;

struct Args {
    addr: String,
    socket: String,
    trust_domain: String,
    namespace: String,
    service: String,
    name: String,
}

fn parse_args() -> Args {
    let mut args = Args {
        addr: "localhost:8443".to_string(),
        socket: "unix:///run/spire/sockets/agent.sock".to_string(),
        trust_domain: "example.org".to_string(),
        namespace: "default".to_string(),
        service: "example".to_string(),
        name: "api-key".to_string(),
    };

    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().expect("missing value for flag");
        match flag.as_str() {
            "--addr" => args.addr = value(),
            "--socket" => args.socket = value(),
            "--trust-domain" => args.trust_domain = value(),
            "--namespace" => args.namespace = value(),
            "--service" => args.service = value(),
            "--name" => args.name = value(),
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

    let mut client = SecretsServiceClient::new(channel);
    let resp = client
        .get_secret(GetSecretRequest {
            namespace: args.namespace,
            service: args.service,
            name: args.name,
        })
        .await?
        .into_inner();

    println!("version={} value={:?}", resp.version, String::from_utf8_lossy(&resp.value));
    Ok(())
}
