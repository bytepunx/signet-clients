//! Demonstrates the intended pattern for a service that pulls its own signet
//! configuration directly, in-memory, and coordinates a safe restart when
//! that configuration changes — without a process host and without ever
//! writing secrets to its environment. Mirrors
//! `go/examples/restart-on-change`.
//!
//! The pattern:
//!  1. Fetch the bundle once at startup and configure the app in memory.
//!  2. Serve traffic normally.
//!  3. Block on `wait_for_restart`, which only returns once signet reports a
//!     change AND this replica has acquired the distributed restart lock —
//!     guaranteeing at most one replica restarts at a time fleet-wide.
//!  4. Do your own graceful shutdown (drain in-flight requests, close
//!     resources).
//!  5. Release the lock, then exit. Kubernetes starts a fresh process, which
//!     repeats from step 1 with the new configuration.
//!
//! Requires the `spiffe-workload` feature:
//!
//! ```text
//! cargo run --example restart_on_change --features spiffe-workload -- \
//!     --addr localhost:8443 \
//!     --socket unix:///run/spire/sockets/agent.sock \
//!     --trust-domain example.org \
//!     --namespace default --service example \
//!     --lock-ttl 30 --debounce 10
//! ```

use std::time::Duration;

use signet_client::dial_workload;
use signet_client::signet::v1::secrets_service_client::SecretsServiceClient;
use signet_client::signet::v1::GetServiceBundleRequest;
use signet_client::wait_for_restart;
use tokio_util::sync::CancellationToken;

struct Args {
    addr: String,
    socket: String,
    trust_domain: String,
    namespace: String,
    service: String,
    lock_ttl_secs: u64,
    debounce_secs: u64,
}

fn parse_args() -> Args {
    let mut args = Args {
        addr: "localhost:8443".to_string(),
        socket: "unix:///run/spire/sockets/agent.sock".to_string(),
        trust_domain: "example.org".to_string(),
        namespace: "default".to_string(),
        service: "example".to_string(),
        lock_ttl_secs: 30,
        debounce_secs: 10,
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
            "--lock-ttl" => args.lock_ttl_secs = value().parse().expect("--lock-ttl must be seconds"),
            "--debounce" => args.debounce_secs = value().parse().expect("--debounce must be seconds"),
            other => panic!("unknown flag {other}"),
        }
    }
    args
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();
    let cancel = CancellationToken::new();

    // SIGTERM/SIGINT should look like "shut down cleanly, no change arrived
    // yet" — cancel the wait so `wait_for_restart` returns promptly instead
    // of blocking forever.
    #[cfg(unix)]
    {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
            tokio::select! {
                _ = sigterm.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
            cancel.cancel();
        });
    }

    let channel = dial_workload(&args.addr, &args.socket, &args.trust_domain).await?;
    let mut client = SecretsServiceClient::new(channel);

    // 1. Fetch once at startup; configure the app in memory. Never write
    // this to the environment or disk.
    let bundle = client
        .get_service_bundle(GetServiceBundleRequest {
            namespace: args.namespace.clone(),
            service: args.service.clone(),
        })
        .await?
        .into_inner();
    eprintln!("configured: config_version={}", bundle.config_version);

    // 2. Serve traffic normally (omitted — this is a minimal example).

    // 3. Block until a change is reported and this replica holds the lock.
    let lock = match wait_for_restart(
        client,
        args.namespace,
        args.service,
        Duration::from_secs(args.lock_ttl_secs),
        Duration::from_secs(args.debounce_secs),
        cancel.clone(),
    )
    .await
    {
        Ok(lock) => lock,
        Err(_) if cancel.is_cancelled() => {
            eprintln!("shutting down: cancelled before any change arrived");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    eprintln!(
        "restart lock acquired: token={} expires_at={:?}",
        lock.token(),
        lock.expires_at()
    );

    // 4. Graceful shutdown: drain in-flight requests, close resources.
    // (omitted — this is a minimal example).

    // 5. Release the lock for the next waiting replica, then exit.
    // Kubernetes restarts the pod; the new process fetches the bundle fresh.
    if let Err(e) = lock.release().await {
        eprintln!("lock release failed (it will still expire via TTL): {e}");
    }
    Ok(())
}
