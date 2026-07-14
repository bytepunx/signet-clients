//! Smoke-test fixture for the Docker/Kubernetes echo harness
//! (`bytepunx/signet-smoke-test`): fetches a service bundle from a real
//! signet + SPIRE deployment, prints it to stdout for log-based
//! verification, then blocks on the coordinated-restart protocol and prints
//! the acquired lock once the harness triggers a bundle change.
//!
//! **TEST-ONLY. This program prints retrieved secrets to stdout — never do
//! this in production code.** See `echo/Dockerfile` for the container build.
//!
//! No CLI flags: every input comes from the environment, since this runs as
//! a container in Kubernetes.
//!
//! Required:
//!   - `SIGNET_ADDR` — signet workload gRPC address, e.g.
//!     `signet.signet.svc.cluster.local:8443`
//!   - `SIGNET_TRUST_DOMAIN` — SPIFFE trust domain
//!   - `SPIFFE_WORKLOAD_SOCKET` — SPIFFE Workload API socket, as a `unix://`
//!     URI, e.g. `unix:///run/spiffe.io/spire-agent.sock`
//!   - `SIGNET_NAMESPACE` — signet namespace to fetch (typically populated
//!     via the Kubernetes Downward API in the Deployment manifest)
//!   - `SIGNET_SERVICE` — signet service to fetch
//!
//! Optional:
//!   - `RESTART_LOCK_TTL_SECONDS` — restart lock TTL; default `30`, and any
//!     missing/unparseable value falls back to the default
//!   - `RESTART_DEBOUNCE_SECONDS` — restart debounce; default `5`, same
//!     fallback behavior
//!
//! Requires the `spiffe-workload` feature:
//!
//! ```text
//! SIGNET_ADDR=localhost:8443 \
//! SIGNET_TRUST_DOMAIN=example.org \
//! SPIFFE_WORKLOAD_SOCKET=unix:///run/spire/sockets/agent.sock \
//! SIGNET_NAMESPACE=default \
//! SIGNET_SERVICE=example \
//!     cargo run --example echo --features spiffe-workload
//! ```
//!
//! Sequence: print the test-only banner; dial signet over SPIFFE mTLS; fetch
//! the service bundle and print it (secrets base64-decoded) as a single
//! `ECHO_BUNDLE: <json>` line; block in `wait_for_restart` until this
//! replica acquires the restart lock; print `ECHO_RESTART: <...>`; release
//! the lock; exit 0. Kubernetes (`restartPolicy: Always`) restarts the pod,
//! and the new instance repeats from the top against whatever changed —
//! that's the behavior this whole harness exists to prove.

use std::collections::BTreeMap;
use std::time::Duration;

use base64::Engine;
use signet_client::dial_workload;
use signet_client::signet::v1::secrets_service_client::SecretsServiceClient;
use signet_client::signet::v1::GetServiceBundleRequest;
use signet_client::wait_for_restart;
use tokio_util::sync::CancellationToken;

/// The exact banner required by the smoke-test harness's log-based
/// verification, and as a plain, unmissable warning to any human who
/// stumbles onto this container's logs.
const BANNER: &str =
    "TEST-ONLY BUILD — DO NOT RUN IN PRODUCTION. This program prints retrieved secrets to stdout.";

/// The default restart lock TTL, seconds, used when `RESTART_LOCK_TTL_SECONDS`
/// is unset or unparseable.
const DEFAULT_LOCK_TTL_SECONDS: u64 = 30;

/// The default restart debounce, seconds, used when `RESTART_DEBOUNCE_SECONDS`
/// is unset or unparseable.
const DEFAULT_DEBOUNCE_SECONDS: u64 = 5;

#[derive(Debug, thiserror::Error)]
enum EchoError {
    #[error(
        "missing required environment variable {0}: this container is meant to run in \
         Kubernetes with all of SIGNET_ADDR, SIGNET_TRUST_DOMAIN, SPIFFE_WORKLOAD_SOCKET, \
         SIGNET_NAMESPACE, and SIGNET_SERVICE set (see the Deployment manifest)"
    )]
    MissingEnvVar(&'static str),

    #[error("secret {name:?} in bundle is not valid base64: {source}")]
    SecretNotBase64 {
        name: String,
        #[source]
        source: base64::DecodeError,
    },
}

struct Config {
    addr: String,
    socket: String,
    trust_domain: String,
    namespace: String,
    service: String,
    lock_ttl: Duration,
    debounce: Duration,
}

fn require_env(name: &'static str) -> Result<String, EchoError> {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => Ok(v),
        _ => Err(EchoError::MissingEnvVar(name)),
    }
}

/// Parses an optional duration-in-seconds env var, falling back to
/// `default` if the variable is unset, empty, or not a valid `u64` — per
/// the harness contract, a bad optional value is not a fatal error.
fn optional_seconds(name: &str, default: u64) -> Duration {
    let secs = std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default);
    Duration::from_secs(secs)
}

fn load_config() -> Result<Config, EchoError> {
    Ok(Config {
        addr: require_env("SIGNET_ADDR")?,
        trust_domain: require_env("SIGNET_TRUST_DOMAIN")?,
        socket: require_env("SPIFFE_WORKLOAD_SOCKET")?,
        namespace: require_env("SIGNET_NAMESPACE")?,
        service: require_env("SIGNET_SERVICE")?,
        lock_ttl: optional_seconds("RESTART_LOCK_TTL_SECONDS", DEFAULT_LOCK_TTL_SECONDS),
        debounce: optional_seconds("RESTART_DEBOUNCE_SECONDS", DEFAULT_DEBOUNCE_SECONDS),
    })
}

/// Converts a `prost_types::Struct` (the wire representation of
/// `google.protobuf.Struct`, which is what signet's `GetServiceBundleResponse.bundle`
/// is made of) into a `serde_json::Value`. Neither `prost-types` nor this
/// crate ship such a conversion, so this is a small local helper rather
/// than new library surface — this example is the only place in the repo
/// that needs to render a bundle as JSON.
fn struct_to_json(s: &prost_types::Struct) -> serde_json::Value {
    serde_json::Value::Object(
        s.fields
            .iter()
            .map(|(k, v)| (k.clone(), value_to_json(v)))
            .collect(),
    )
}

fn value_to_json(v: &prost_types::Value) -> serde_json::Value {
    use prost_types::value::Kind;
    match &v.kind {
        None | Some(Kind::NullValue(_)) => serde_json::Value::Null,
        Some(Kind::NumberValue(n)) => serde_json::Number::from_f64(*n)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        Some(Kind::StringValue(s)) => serde_json::Value::String(s.clone()),
        Some(Kind::BoolValue(b)) => serde_json::Value::Bool(*b),
        Some(Kind::StructValue(s)) => struct_to_json(s),
        Some(Kind::ListValue(l)) => serde_json::Value::Array(l.values.iter().map(value_to_json).collect()),
    }
}

/// Renders `bundle` as the JSON payload for the `ECHO_BUNDLE:` log line:
/// config fields stay at the top level exactly as signet returned them, but
/// the reserved `"secrets"` sub-map has its values base64-decoded (signet
/// returns secret values as base64-encoded plaintext; printing that
/// undecoded would just be testing base64, not the actual secret value).
fn bundle_to_echo_json(bundle: &prost_types::Struct) -> Result<serde_json::Value, EchoError> {
    let mut top = match struct_to_json(bundle) {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };

    if let Some(serde_json::Value::Object(secrets)) = top.get_mut("secrets") {
        let mut decoded = serde_json::Map::with_capacity(secrets.len());
        for (name, value) in secrets.iter() {
            let encoded = match value {
                serde_json::Value::String(s) => s.as_str(),
                // Not a string: leave whatever it is untouched rather than
                // silently dropping/misreporting it.
                other => {
                    decoded.insert(name.clone(), other.clone());
                    continue;
                }
            };
            let plaintext = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|source| EchoError::SecretNotBase64 {
                    name: name.clone(),
                    source,
                })?;
            decoded.insert(
                name.clone(),
                serde_json::Value::String(String::from_utf8_lossy(&plaintext).into_owned()),
            );
        }
        *top.get_mut("secrets").expect("checked Some above") = serde_json::Value::Object(decoded);
    }

    Ok(serde_json::Value::Object(top))
}

/// Installs a Ctrl-C/SIGTERM handler that cancels `cancel` on either signal,
/// so every blocking point in `main` (dial, RPCs, `wait_for_restart`) can
/// race it via `tokio::select!` and exit 0 promptly instead of hanging.
fn install_signal_handler(cancel: CancellationToken) {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("install SIGTERM handler");
            tokio::select! {
                _ = sigterm.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        eprintln!("received shutdown signal, exiting gracefully");
        cancel.cancel();
    });
}

#[tokio::main]
async fn main() {
    // Unconditionally the very first thing this program does.
    println!("{BANNER}");

    if let Err(e) = run().await {
        // `Box<dyn Error>`'s `Display` (not `Debug`) surfaces the specific,
        // human-readable message each error variant defines above (e.g.
        // exactly which environment variable is missing) — this container's
        // only observable output is its logs, so that clarity matters.
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;

    let cancel = CancellationToken::new();
    install_signal_handler(cancel.clone());

    let channel = tokio::select! {
        res = dial_workload(&config.addr, &config.socket, &config.trust_domain) => res?,
        () = cancel.cancelled() => {
            eprintln!("cancelled before connecting to signet");
            return Ok(());
        }
    };
    let mut client = SecretsServiceClient::new(channel);

    let bundle_resp = tokio::select! {
        res = client.get_service_bundle(GetServiceBundleRequest {
            namespace: config.namespace.clone(),
            service: config.service.clone(),
        }) => res?.into_inner(),
        () = cancel.cancelled() => {
            eprintln!("cancelled before fetching the service bundle");
            return Ok(());
        }
    };
    eprintln!(
        "fetched bundle: namespace={} service={} config_version={}",
        config.namespace, config.service, bundle_resp.config_version
    );

    let empty = prost_types::Struct {
        fields: BTreeMap::new(),
    };
    let bundle = bundle_resp.bundle.as_ref().unwrap_or(&empty);
    let echo_json = bundle_to_echo_json(bundle)?;
    println!("ECHO_BUNDLE: {}", serde_json::to_string(&echo_json)?);

    // Blocks, potentially indefinitely — expected steady-state until the
    // harness changes this service's bundle and this replica wins the
    // restart lock.
    let lock = match wait_for_restart(
        client,
        config.namespace,
        config.service,
        config.lock_ttl,
        config.debounce,
        cancel.clone(),
    )
    .await
    {
        Ok(lock) => lock,
        Err(_) if cancel.is_cancelled() => {
            eprintln!("cancelled while waiting for a restart");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    println!(
        "ECHO_RESTART: token={} expires_at={:?}",
        lock.token(),
        lock.expires_at()
    );

    // Release for the next waiting replica; the lock's TTL would eventually
    // expire on its own, but releasing promptly keeps the fleet-wide
    // restart serialized without waiting out the TTL.
    if let Err(e) = lock.release().await {
        eprintln!("lock release failed (it will still expire via TTL): {e}");
    }

    // Kubernetes (restartPolicy: Always) restarts the pod; the new instance
    // repeats from the top against whatever changed.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_to_echo_json_decodes_secrets_and_keeps_config_at_top_level() {
        let mut secrets_fields = BTreeMap::new();
        secrets_fields.insert(
            "api-key".to_string(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue(
                    base64::engine::general_purpose::STANDARD.encode(b"super-secret"),
                )),
            },
        );
        let secrets_struct = prost_types::Struct { fields: secrets_fields };

        let mut fields = BTreeMap::new();
        fields.insert(
            "log_level".to_string(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue("debug".to_string())),
            },
        );
        fields.insert(
            "secrets".to_string(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StructValue(secrets_struct)),
            },
        );
        let bundle = prost_types::Struct { fields };

        let json = bundle_to_echo_json(&bundle).expect("conversion should succeed");
        assert_eq!(json["log_level"], serde_json::json!("debug"));
        assert_eq!(json["secrets"]["api-key"], serde_json::json!("super-secret"));
    }

    #[test]
    fn bundle_to_echo_json_rejects_non_base64_secret_with_a_named_error() {
        let mut secrets_fields = BTreeMap::new();
        secrets_fields.insert(
            "bad".to_string(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue("not-base64!!!".to_string())),
            },
        );
        let mut fields = BTreeMap::new();
        fields.insert(
            "secrets".to_string(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StructValue(prost_types::Struct {
                    fields: secrets_fields,
                })),
            },
        );
        let bundle = prost_types::Struct { fields };

        let err = bundle_to_echo_json(&bundle).unwrap_err();
        assert!(err.to_string().contains("bad"));
    }
}
