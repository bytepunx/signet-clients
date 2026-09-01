//! Connection helpers for talking to a signet server.
//!
//! Mirrors `go/client.go`: [`dial_admin`] opens a bearer-token connection to
//! the operator-facing `AdminService`/`GitOpsService` listener, applying the
//! same loopback-defaults-to-plaintext logic (with the same `force_tls`/
//! `plaintext` overrides) as the Go client and the `signet` CLI.
//! [`dial_workload`] (behind the `spiffe-workload` feature) opens a
//! SPIFFE-mTLS connection to the workload-facing `SecretsService` listener,
//! retrying automatically — no opt-in required — if it loses the SPIRE
//! identity-registration-propagation race described in its doc comment. Its
//! `Channel` is also usable with [`gitops_client`] for the subset of
//! `GitOpsService` reachable this way (`SyncBundle`, `PatchServiceConfig`,
//! `GetSOPSPublicKey`) without ever holding an admin bearer token
//! (bytepunx/signet#23, #38, #78) — see [`gitops_client`]'s doc comment and
//! `examples/gitops_workload.rs`.

use std::net::IpAddr;
use std::path::Path;

use tonic::codegen::{Body, Bytes, StdError};
use tonic::service::interceptor::InterceptedService;
use tonic::service::Interceptor;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tonic::{Request, Status};

use crate::admin::v1::admin_service_client::AdminServiceClient;
use crate::admin::v1::git_ops_service_client::GitOpsServiceClient;

/// Errors returned by the connection helpers in this module.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// `dial_admin` was called with an empty (or whitespace-only) token.
    #[error("token must not be empty")]
    EmptyToken,

    /// A CA PEM bundle was supplied but contained no parseable certificates.
    #[error("invalid CA PEM bundle: no certificates found")]
    InvalidCaPem,

    /// `dial_admin` was called with both `force_tls` and `plaintext` set.
    /// They request opposite overrides of the loopback heuristic, so
    /// exactly one (or neither) may be set. See [`dial_admin`]'s doc
    /// comment.
    #[error("force_tls and plaintext are mutually exclusive")]
    ForceTlsPlaintextConflict,

    /// `dial_admin` was called with `plaintext` set and a non-empty
    /// `ca_pem`. There is no meaningful CA to verify against when the
    /// transport isn't TLS at all. See [`dial_admin`]'s doc comment.
    #[error("plaintext and ca_pem are mutually exclusive")]
    PlaintextCaPemConflict,

    /// A CA PEM bundle was supplied but failed to parse.
    #[error("invalid CA PEM bundle: {0}")]
    CaPemParse(String),

    /// The target address could not be turned into a valid gRPC endpoint URI.
    #[error("invalid address {addr:?}: {source}")]
    InvalidEndpoint {
        addr: String,
        #[source]
        source: tonic::transport::Error,
    },

    /// Failed to establish the transport connection.
    #[error("connect to {addr:?}: {source}")]
    Connect {
        addr: String,
        #[source]
        source: tonic::transport::Error,
    },

    /// Reading a CA bundle from disk (see [`read_ca_file`]) failed.
    #[error("read CA file {path:?}: {source}")]
    ReadCaFile {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// Failed to connect to the SPIFFE Workload API.
    #[cfg(feature = "spiffe-workload")]
    #[error("connect to SPIFFE Workload API at {socket:?}: {source}")]
    WorkloadApi {
        socket: String,
        #[source]
        source: spiffe::x509_source::X509SourceError,
    },

    /// [`dial_workload`]'s identity-readiness probe kept seeing "no
    /// identity issued" through its full retry budget (see
    /// `dial_workload`'s doc comment for the schedule and why this retry
    /// exists — bytepunx/signet-clients#33) without ever observing success
    /// or a different failure.
    #[cfg(feature = "spiffe-workload")]
    #[error("connect to SPIFFE workload API at {socket:?}: no identity issued after {attempts} attempts: {source}")]
    WorkloadNoIdentityIssued {
        socket: String,
        attempts: usize,
        #[source]
        source: spiffe::WorkloadApiError,
    },

    /// [`dial_workload`]'s identity-readiness probe failed for a reason
    /// other than "no identity issued" (a bad `socket_path`, an expired or
    /// canceled deadline, a malformed `trust_domain`, a genuine
    /// authorization problem once identity issuance is actually broken
    /// rather than merely delayed, ...) — surfaced immediately, unretried,
    /// so this never masks a real misconfiguration as a transient blip.
    #[cfg(feature = "spiffe-workload")]
    #[error("connect to SPIFFE workload API at {socket:?}: {source}")]
    WorkloadProbe {
        socket: String,
        #[source]
        source: spiffe::WorkloadApiError,
    },

    /// The supplied trust domain string was not a valid SPIFFE trust domain.
    #[cfg(feature = "spiffe-workload")]
    #[error("invalid trust domain {0:?}: {1}")]
    InvalidTrustDomain(String, String),

    /// Failed to build the SPIFFE mTLS `rustls::ClientConfig`.
    #[cfg(feature = "spiffe-workload")]
    #[error("build SPIFFE mTLS client config: {0}")]
    SpiffeTls(String),

    /// The target address was not a valid `host:port` pair.
    #[cfg(feature = "spiffe-workload")]
    #[error("invalid workload address {0:?}: expected host:port")]
    InvalidWorkloadAddress(String),

    /// The underlying TCP connection or TLS handshake to the workload
    /// listener failed.
    #[cfg(feature = "spiffe-workload")]
    #[error("connect to {addr:?}: {source}")]
    WorkloadConnect {
        addr: String,
        #[source]
        source: std::io::Error,
    },
}

/// Injects `Authorization: Bearer <token>` into every outgoing RPC's
/// metadata. Constructed internally by [`dial_admin`]; exposed so callers
/// can see the concrete type of [`AdminChannel`].
#[derive(Clone)]
pub struct TokenInterceptor {
    header_value: tonic::metadata::MetadataValue<tonic::metadata::Ascii>,
}

impl Interceptor for TokenInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        req.metadata_mut()
            .insert("authorization", self.header_value.clone());
        Ok(req)
    }
}

/// The transport type returned by [`dial_admin`]: a `tonic` [`Channel`] with
/// a [`TokenInterceptor`] attached. Pass it to [`admin_client`] or
/// [`gitops_client`] to get a typed RPC client.
pub type AdminChannel = InterceptedService<Channel, TokenInterceptor>;

/// Opens a gRPC connection to signet's admin listener, injecting `token`
/// into every RPC as a bearer credential.
///
/// Transport security is chosen automatically from `addr`:
/// - Loopback addresses (`localhost`, `127.0.0.1`, `::1` — the documented
///   `kubectl port-forward` workflow) default to plaintext.
/// - Every other address is upgraded to TLS automatically, using the
///   system trust store, or the CA in `ca_pem` if provided.
///
/// `force_tls` and `plaintext` both override that heuristic, in opposite
/// directions:
/// - `force_tls` requests TLS even for a loopback address (e.g. testing a
///   real TLS-terminating proxy locally).
/// - `plaintext` forces insecure transport credentials even for a
///   non-loopback address, bypassing the loopback heuristic entirely. This
///   is required once signet exposes a real in-cluster admin listener
///   (bytepunx/signet#19): dialing that Service by its cluster-DNS name is
///   a non-loopback address, but the listener is intentionally still
///   plaintext-behind-bearer-token, not TLS-terminated — without
///   `plaintext`, the loopback heuristic would pick TLS and the handshake
///   would fail immediately ("wrong version number") against a server that
///   never speaks TLS on that listener. See bytepunx/signet-clients#32.
///
/// Per-RPC bearer-token authentication (the actual mechanism signet uses to
/// authenticate the caller) is unaffected either way — `plaintext` only
/// changes the transport, never who signet trusts the caller to be.
///
/// `force_tls` and `plaintext` are mutually exclusive with each other
/// ([`ClientError::ForceTlsPlaintextConflict`]), and `plaintext` is
/// mutually exclusive with a non-empty `ca_pem`
/// ([`ClientError::PlaintextCaPemConflict`]) — there is no meaningful CA to
/// verify against when the transport isn't TLS at all.
///
/// Returns [`ClientError::EmptyToken`] if `token` is empty or
/// whitespace-only, before any connection attempt is made.
pub async fn dial_admin(
    addr: impl AsRef<str>,
    token: impl AsRef<str>,
    ca_pem: Option<&[u8]>,
    force_tls: bool,
    plaintext: bool,
) -> Result<AdminChannel, ClientError> {
    let addr = addr.as_ref();
    let token = token.as_ref().trim();
    if token.is_empty() {
        return Err(ClientError::EmptyToken);
    }

    let decision = admin_transport_decision(addr, ca_pem, force_tls, plaintext)?;
    let uri = format!(
        "{}://{addr}",
        if decision.requires_tls() { "https" } else { "http" }
    );

    let mut endpoint = Endpoint::from_shared(uri).map_err(|source| ClientError::InvalidEndpoint {
        addr: addr.to_string(),
        source,
    })?;
    if let TransportDecision::Tls(tls_config) = decision {
        endpoint = endpoint
            .tls_config(tls_config)
            .map_err(|source| ClientError::InvalidEndpoint {
                addr: addr.to_string(),
                source,
            })?;
    }

    let channel = endpoint
        .connect()
        .await
        .map_err(|source| ClientError::Connect {
            addr: addr.to_string(),
            source,
        })?;

    let header_value = format!("Bearer {token}")
        .parse()
        .expect("Bearer <token> is always valid ASCII metadata once token is trimmed non-empty");

    Ok(InterceptedService::new(
        channel,
        TokenInterceptor { header_value },
    ))
}

/// Returns an `AdminService` client bound to `channel`.
///
/// Generic over the underlying `tonic` service type so that both
/// [`AdminChannel`] (from [`dial_admin`], bearer-token auth) and a plain
/// [`Channel`] (from `dial_workload`, behind the `spiffe-workload` feature)
/// work as `channel` — the bound is exactly what the generated
/// `AdminServiceClient<T>::new` requires. In practice signet's server only
/// accepts admin-token auth for `AdminService` itself, so `dial_workload`'s
/// channel is mainly useful with [`gitops_client`], not this function; the
/// generic signature is kept the same as `gitops_client`'s for consistency.
pub fn admin_client<T>(channel: T) -> AdminServiceClient<T>
where
    T: tonic::client::GrpcService<tonic::body::Body>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    AdminServiceClient::new(channel)
}

/// Returns a `GitOpsService` client bound to `channel`.
///
/// `channel` may come from either [`dial_admin`] ([`AdminChannel`]:
/// bearer-token auth, full access) or `dial_workload` (behind the
/// `spiffe-workload` feature; a plain [`Channel`]: SPIFFE mTLS, the caller's
/// own identity) — signet's server accepts both for `SyncBundle`,
/// `PatchServiceConfig`, and `GetSOPSPublicKey`, letting a workload
/// self-service its own bundle/config writes and fetch the active SOPS
/// public key without ever holding an admin token (bytepunx/signet#23, #38,
/// #78). Cross-namespace/service writes still require an explicit
/// `CreatePolicy` grant from an operator. See `examples/gitops_workload.rs`
/// for a runnable demonstration.
///
/// This function is generic over the underlying `tonic` service type,
/// rather than fixed to [`AdminChannel`], purely so both channel kinds
/// type-check here — the trait bound below is copied verbatim from the
/// `where` clause `tonic-build` generates on
/// `GitOpsServiceClient<T>::new`/`with_origin`/etc., not hand-picked.
pub fn gitops_client<T>(channel: T) -> GitOpsServiceClient<T>
where
    T: tonic::client::GrpcService<tonic::body::Body>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    GitOpsServiceClient::new(channel)
}

/// Reads a PEM CA bundle from `path` for use with [`dial_admin`].
pub fn read_ca_file(path: impl AsRef<Path>) -> Result<Vec<u8>, ClientError> {
    let path_ref = path.as_ref();
    std::fs::read(path_ref).map_err(|source| ClientError::ReadCaFile {
        path: path_ref.display().to_string(),
        source,
    })
}

#[derive(Debug)]
pub(crate) enum TransportDecision {
    Plaintext,
    Tls(ClientTlsConfig),
}

impl TransportDecision {
    pub(crate) fn requires_tls(&self) -> bool {
        matches!(self, TransportDecision::Tls(_))
    }
}

pub(crate) fn admin_transport_decision(
    addr: &str,
    ca_pem: Option<&[u8]>,
    force_tls: bool,
    plaintext: bool,
) -> Result<TransportDecision, ClientError> {
    let ca_pem_non_empty = ca_pem.map(|pem| !pem.is_empty()).unwrap_or(false);

    if plaintext && force_tls {
        return Err(ClientError::ForceTlsPlaintextConflict);
    }
    if plaintext && ca_pem_non_empty {
        return Err(ClientError::PlaintextCaPemConflict);
    }
    if plaintext {
        return Ok(TransportDecision::Plaintext);
    }

    let host = host_of(addr);
    let use_tls = force_tls || ca_pem_non_empty || !is_loopback_host(&host);

    if !use_tls {
        return Ok(TransportDecision::Plaintext);
    }

    let mut tls = ClientTlsConfig::new();
    if let Some(pem) = ca_pem {
        if !pem.is_empty() {
            validate_ca_pem(pem)?;
            tls = tls.ca_certificate(Certificate::from_pem(pem));
        }
    }
    Ok(TransportDecision::Tls(tls))
}

/// Extracts the host portion of a `host:port` (or bracketed IPv6
/// `[::1]:port`) address, mirroring Go's `net.SplitHostPort` fallback
/// behavior: if `addr` doesn't look like `host:port`, the whole string is
/// treated as the host.
pub(crate) fn host_of(addr: &str) -> String {
    if let Ok(sock) = addr.parse::<std::net::SocketAddr>() {
        return sock.ip().to_string();
    }
    if let Some(idx) = addr.rfind(':') {
        let (host_part, port_part) = (&addr[..idx], &addr[idx + 1..]);
        if !host_part.is_empty() && !port_part.is_empty() && port_part.bytes().all(|b| b.is_ascii_digit()) {
            return host_part.trim_start_matches('[').trim_end_matches(']').to_string();
        }
    }
    addr.to_string()
}

pub(crate) fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

fn validate_ca_pem(pem: &[u8]) -> Result<(), ClientError> {
    let mut reader = std::io::BufReader::new(pem);
    let mut count = 0usize;
    for item in rustls_pemfile::certs(&mut reader) {
        match item {
            Ok(_) => count += 1,
            Err(e) => return Err(ClientError::CaPemParse(e.to_string())),
        }
    }
    if count == 0 {
        return Err(ClientError::InvalidCaPem);
    }
    Ok(())
}

#[cfg(feature = "spiffe-workload")]
mod workload {
    use super::ClientError;
    use std::future::Future;
    use std::net::ToSocketAddrs;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use tokio::net::TcpStream;
    use tonic::codegen::http::Uri;
    use tonic::codegen::Service;
    use tonic::transport::{Channel, Endpoint};

    /// The wait before each retry [`dial_workload`]'s identity-readiness
    /// probe makes after the Workload API reports "no identity issued" (see
    /// `dial_workload`'s doc comment): 1s, 2s, 4s, 8s — exponential,
    /// doubling each time and capped at 8s. This is the exact schedule
    /// verified working in a real downstream consumer that hit this race
    /// (bytepunx/signet-clients#33 — bytepunx/kluster's RabbitMQ
    /// credential-provisioning Job, which retries its own dial 5 times
    /// total with this identical backoff), so `WORKLOAD_DIAL_BACKOFF.len()`
    /// retries are made beyond the initial attempt —
    /// `WORKLOAD_DIAL_MAX_ATTEMPTS` total — with a worst case of roughly
    /// 15s of sleeping before `dial_workload` gives up.
    const WORKLOAD_DIAL_BACKOFF: [Duration; 4] = [
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(4),
        Duration::from_secs(8),
    ];

    /// The total number of identity-readiness probes [`dial_workload`]
    /// makes (the initial attempt plus `WORKLOAD_DIAL_BACKOFF.len()`
    /// retries) before giving up.
    const WORKLOAD_DIAL_MAX_ATTEMPTS: usize = WORKLOAD_DIAL_BACKOFF.len() + 1;

    /// Calls `probe` repeatedly, retrying per [`WORKLOAD_DIAL_BACKOFF`] (via
    /// `tokio::time::sleep`, so tests can drive this deterministically
    /// with a paused Tokio time source — see this module's tests) as long
    /// as it keeps failing with `WorkloadApiError::NoIdentityIssued`.
    /// Returns `Ok(())` as soon as `probe` succeeds, a
    /// [`ClientError::WorkloadProbe`] on the first error that isn't "no
    /// identity issued", or a [`ClientError::WorkloadNoIdentityIssued`]
    /// naming the last such failure once `WORKLOAD_DIAL_MAX_ATTEMPTS` is
    /// exhausted.
    async fn retry_until_identity_issued<F, Fut>(
        socket_path: &str,
        mut probe: F,
    ) -> Result<(), ClientError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<(), spiffe::WorkloadApiError>>,
    {
        let mut last_err: Option<spiffe::WorkloadApiError> = None;
        // The delay to sleep *before* each attempt: none before the first
        // (probe immediately), then one entry per retry per
        // WORKLOAD_DIAL_BACKOFF. This yields exactly
        // WORKLOAD_DIAL_MAX_ATTEMPTS items, so the loop below never needs
        // to index WORKLOAD_DIAL_BACKOFF by a separately tracked attempt
        // counter.
        let delays_before_each_attempt =
            std::iter::once(None).chain(WORKLOAD_DIAL_BACKOFF.into_iter().map(Some));

        for delay in delays_before_each_attempt {
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            match probe().await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if !matches!(e, spiffe::WorkloadApiError::NoIdentityIssued) {
                        return Err(ClientError::WorkloadProbe {
                            socket: socket_path.to_string(),
                            source: e,
                        });
                    }
                    last_err = Some(e);
                }
            }
        }
        Err(ClientError::WorkloadNoIdentityIssued {
            socket: socket_path.to_string(),
            attempts: WORKLOAD_DIAL_MAX_ATTEMPTS,
            source: last_err
                .expect("loop always records last_err before exhausting WORKLOAD_DIAL_MAX_ATTEMPTS"),
        })
    }

    /// Probes the Workload API at `socket_path` with a single-shot,
    /// non-watching fetch — see [`dial_workload`]'s doc comment for why a
    /// plain `fetch_x509_context` call, and not `X509Source::builder()`, is
    /// used here.
    async fn probe_identity_issued(socket_path: &str) -> Result<(), spiffe::WorkloadApiError> {
        let client = spiffe::WorkloadApiClient::connect_to(socket_path).await?;
        client.fetch_x509_context().await?;
        Ok(())
    }

    /// Opens a gRPC connection to signet's workload listener, authenticating
    /// via SPIFFE mTLS.
    ///
    /// `socket_path` is the SPIFFE Workload API socket (e.g.
    /// `unix:///run/spire/sockets/agent.sock`); `trust_domain` must match the
    /// trust domain of the target signet instance and of this workload's own
    /// SVID (federation across trust domains is not supported by this
    /// helper). The server's presented SPIFFE ID is verified to be a member
    /// of `trust_domain`, mirroring Go's
    /// `tlsconfig.AuthorizeMemberOf` — connecting to a server whose identity
    /// is outside that trust domain fails the handshake.
    ///
    /// The returned [`Channel`](tonic::transport::Channel) is also usable
    /// with [`gitops_client`](super::gitops_client) for the subset of
    /// `GitOpsService` reachable this way (`SyncBundle`,
    /// `PatchServiceConfig`, `GetSOPSPublicKey`) without needing an admin
    /// bearer token at all. See
    /// [`gitops_client`](super::gitops_client)'s doc comment and
    /// `examples/gitops_workload.rs`.
    ///
    /// `dial_workload` retries automatically — no opt-in required — if the
    /// Workload API reports "no identity issued" before it can hand back a
    /// connection. This is a real, verified-in-production race, not
    /// speculative hardening: SPIRE's controller-manager reconciles a
    /// brand-new pod's SPIFFE identity registration reactively, off the
    /// pod's own creation event, and that registration takes a few seconds
    /// to propagate from there to the node-local SPIRE agent this dials
    /// over `socket_path`. A freshly-created pod's very first
    /// `dial_workload` call — a Job's is the sharpest case, since a Job has
    /// no prior pod that might have already won this race for the same
    /// ServiceAccount — can lose it outright and see "no identity issued"
    /// even though the identity shows up moments later. See
    /// bytepunx/signet-clients#33 for the full writeup, including where
    /// this was first hit (bytepunx/kluster's RabbitMQ
    /// credential-provisioning Job).
    ///
    /// The retry makes up to `WORKLOAD_DIAL_MAX_ATTEMPTS` (5) attempts total
    /// — the initial attempt plus up to 4 retries — backing off per
    /// `WORKLOAD_DIAL_BACKOFF` (1s, 2s, 4s, 8s) between them. Only the "no
    /// identity issued" failure is retried: every other error (a bad
    /// `socket_path`, a malformed `trust_domain`, a genuine authorization
    /// problem once identity issuance is actually broken rather than merely
    /// delayed, ...) is returned to the caller immediately, unretried, so
    /// this never masks a real misconfiguration as a transient blip. The
    /// retry probes with a single-shot, non-watching
    /// `WorkloadApiClient::fetch_x509_context` call rather than the
    /// long-lived `X509Source` constructor used below, deliberately:
    /// `X509Source`'s own initial sync already retries transient Workload
    /// API failures forever with its own internal, unbounded, unobservable
    /// backoff, which would silently absorb the exact "no identity issued"
    /// signal this retry needs to see and pace itself against. Once the
    /// probe confirms identity is issued, constructing the real
    /// `X509Source` below establishes near-instantly in the common case;
    /// its own internal retry remains as a safety net for any further
    /// transient hiccup, but the race this function exists to close has
    /// already been won by the probe.
    ///
    /// The returned [`Channel`] is backed by a live `spiffe::X509Source`
    /// that keeps rotating its SVID/trust bundle in the background for the
    /// life of the process (or until the channel and all its clones are
    /// dropped) — there is no separate "closer" to call, unlike the Go
    /// client's `DialWorkload`, because the underlying `spiffe-rustls`
    /// crate takes ownership of the source once building the TLS config.
    pub async fn dial_workload(
        addr: impl AsRef<str>,
        socket_path: impl AsRef<str>,
        trust_domain: impl AsRef<str>,
    ) -> Result<Channel, ClientError> {
        let addr = addr.as_ref().to_string();
        let socket_path = socket_path.as_ref().to_string();
        let trust_domain = trust_domain.as_ref().to_string();

        retry_until_identity_issued(&socket_path, || probe_identity_issued(&socket_path)).await?;

        let source = spiffe::X509Source::builder()
            .endpoint(&socket_path)
            .build()
            .await
            .map_err(|source| ClientError::WorkloadApi {
                socket: socket_path.clone(),
                source,
            })?;

        let td = spiffe::TrustDomain::try_from(trust_domain.as_str())
            .map_err(|e| ClientError::InvalidTrustDomain(trust_domain.clone(), e.to_string()))?;

        let authorizer = spiffe_rustls::authorizer::trust_domains([td.clone()])
            .map_err(|e| ClientError::SpiffeTls(e.to_string()))?;

        let tls_config = spiffe_rustls::mtls_client(source)
            .authorize(authorizer)
            .trust_domain_policy(spiffe_rustls::TrustDomainPolicy::LocalOnly(td))
            .with_alpn_protocols([b"h2".to_vec()])
            .build()
            .map_err(|e| ClientError::SpiffeTls(e.to_string()))?;

        // The SPIFFE verifier authorizes purely on the SPIFFE ID URI SAN, not
        // the TLS server_name (see spiffe-rustls's verifier docs), so any
        // valid ServerName works here; we use the target host for clarity in
        // logs/debugging even though it isn't cryptographically checked.
        let host = super::host_of(&addr);
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|_| ClientError::InvalidWorkloadAddress(addr.clone()))?;

        let connector = SpiffeConnector {
            target_addr: addr.clone(),
            tls_config: Arc::new(tls_config),
            server_name,
        };

        // "http://", not "https://": SpiffeConnector performs the TLS
        // handshake itself (see its Service::call impl above) and hands
        // tonic an already-secured stream. An "https://" endpoint URI here
        // would make tonic expect its own .tls_config() to be set and it
        // would reject the connection with HttpsUriWithoutTlsSupport before
        // ever invoking the connector — the scheme only selects tonic's own
        // request routing/validation, not what happens on the wire.
        let endpoint =
            Endpoint::from_shared(format!("http://{addr}")).map_err(|source| {
                ClientError::InvalidEndpoint {
                    addr: addr.clone(),
                    source,
                }
            })?;

        endpoint
            .connect_with_connector(connector)
            .await
            .map_err(|source| ClientError::Connect { addr, source })
    }

    #[derive(Clone)]
    struct SpiffeConnector {
        target_addr: String,
        tls_config: Arc<rustls::ClientConfig>,
        server_name: rustls::pki_types::ServerName<'static>,
    }

    impl Service<Uri> for SpiffeConnector {
        type Response = hyper_util::rt::TokioIo<tokio_rustls::client::TlsStream<TcpStream>>;
        type Error = ClientError;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _uri: Uri) -> Self::Future {
            let target_addr = self.target_addr.clone();
            let tls_config = self.tls_config.clone();
            let server_name = self.server_name.clone();

            Box::pin(async move {
                let socket_addr = target_addr
                    .to_socket_addrs()
                    .map_err(|source| ClientError::WorkloadConnect {
                        addr: target_addr.clone(),
                        source,
                    })?
                    .next()
                    .ok_or_else(|| ClientError::InvalidWorkloadAddress(target_addr.clone()))?;

                let tcp = TcpStream::connect(socket_addr).await.map_err(|source| {
                    ClientError::WorkloadConnect {
                        addr: target_addr.clone(),
                        source,
                    }
                })?;
                let _ = tcp.set_nodelay(true);

                let connector = tokio_rustls::TlsConnector::from(tls_config);
                let tls_stream = connector
                    .connect(server_name, tcp)
                    .await
                    .map_err(|source| ClientError::WorkloadConnect {
                        addr: target_addr,
                        source,
                    })?;

                Ok(hyper_util::rt::TokioIo::new(tls_stream))
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Compile-time proof that dial_workload's return type — a plain
        // `tonic::transport::Channel`, per its signature above — satisfies
        // whatever bound gitops_client/admin_client require. This function
        // is never called; if dial_workload's return type ever stopped
        // matching that bound, `cargo test --all-features` (which compiles
        // this module) would fail to build, catching the regression this
        // whole change exists to fix without needing a live signet server
        // or SPIRE agent.
        #[allow(dead_code)]
        fn _dial_workload_channel_satisfies_gitops_and_admin_client_bound(channel: Channel) {
            let _ = super::super::gitops_client(channel.clone());
            let _ = super::super::admin_client(channel);
        }

        fn no_identity_issued() -> spiffe::WorkloadApiError {
            spiffe::WorkloadApiError::NoIdentityIssued
        }

        fn permission_denied(msg: &str) -> spiffe::WorkloadApiError {
            spiffe::WorkloadApiError::PermissionDenied(msg.to_string())
        }

        #[test]
        fn workload_dial_backoff_matches_verified_kluster_schedule() {
            // The exact schedule kluster's hand-rolled retry loop verified
            // working before this was moved into the library (see
            // bytepunx/signet-clients#33).
            assert_eq!(
                WORKLOAD_DIAL_BACKOFF,
                [
                    Duration::from_secs(1),
                    Duration::from_secs(2),
                    Duration::from_secs(4),
                    Duration::from_secs(8),
                ]
            );
            assert_eq!(WORKLOAD_DIAL_MAX_ATTEMPTS, 5);
        }

        #[tokio::test]
        async fn retry_until_identity_issued_succeeds_immediately() {
            let calls = Arc::new(AtomicUsize::new(0));
            let calls_probe = calls.clone();

            let result = retry_until_identity_issued("unix:///test.sock", move || {
                let calls = calls_probe.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            })
            .await;

            assert!(result.is_ok());
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "a successful first probe must not retry"
            );
        }

        #[tokio::test(start_paused = true)]
        async fn retry_until_identity_issued_retries_no_identity_issued_then_succeeds() {
            let calls = Arc::new(AtomicUsize::new(0));
            let calls_probe = calls.clone();
            let start = tokio::time::Instant::now();

            let result = retry_until_identity_issued("unix:///test.sock", move || {
                let calls = calls_probe.clone();
                async move {
                    let attempt = calls.fetch_add(1, Ordering::SeqCst);
                    if attempt < 2 {
                        Err(no_identity_issued())
                    } else {
                        Ok(())
                    }
                }
            })
            .await;

            assert!(result.is_ok());
            assert_eq!(
                calls.load(Ordering::SeqCst),
                3,
                "expected 2 failed probes then 1 succeeding probe"
            );
            // Backoff between attempts 0->1 is 1s and 1->2 is 2s: 3s total,
            // no more (the loop must stop backing off once probe succeeds).
            assert_eq!(start.elapsed(), Duration::from_secs(1 + 2));
        }

        #[tokio::test]
        async fn retry_until_identity_issued_returns_other_error_immediately_unretried() {
            let calls = Arc::new(AtomicUsize::new(0));
            let calls_probe = calls.clone();

            let err = retry_until_identity_issued("unix:///test.sock", move || {
                let calls = calls_probe.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err(permission_denied("selectors do not match"))
                }
            })
            .await
            .unwrap_err();

            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "a non-'no identity issued' failure must never be retried"
            );
            match err {
                ClientError::WorkloadProbe { socket, source } => {
                    assert_eq!(socket, "unix:///test.sock");
                    assert!(matches!(
                        source,
                        spiffe::WorkloadApiError::PermissionDenied(_)
                    ));
                }
                other => panic!("expected ClientError::WorkloadProbe, got {other:?}"),
            }
        }

        #[tokio::test(start_paused = true)]
        async fn retry_until_identity_issued_exhausts_after_five_attempts_with_full_backoff() {
            let calls = Arc::new(AtomicUsize::new(0));
            let calls_probe = calls.clone();
            let start = tokio::time::Instant::now();

            let err = retry_until_identity_issued("unix:///test.sock", move || {
                let calls = calls_probe.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err(no_identity_issued())
                }
            })
            .await
            .unwrap_err();

            assert_eq!(
                calls.load(Ordering::SeqCst),
                WORKLOAD_DIAL_MAX_ATTEMPTS,
                "expected exactly WORKLOAD_DIAL_MAX_ATTEMPTS probes when every one fails with no identity issued"
            );
            // Full backoff schedule elapses: 1 + 2 + 4 + 8 = 15s.
            assert_eq!(start.elapsed(), Duration::from_secs(1 + 2 + 4 + 8));

            match err {
                ClientError::WorkloadNoIdentityIssued {
                    socket,
                    attempts,
                    source,
                } => {
                    assert_eq!(socket, "unix:///test.sock");
                    assert_eq!(attempts, WORKLOAD_DIAL_MAX_ATTEMPTS);
                    assert!(matches!(source, spiffe::WorkloadApiError::NoIdentityIssued));
                }
                other => panic!("expected ClientError::WorkloadNoIdentityIssued, got {other:?}"),
            }
        }
    }
}

#[cfg(feature = "spiffe-workload")]
pub use workload::dial_workload;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_loopback_host_matches_go_client_table() {
        let cases: &[(&str, bool)] = &[
            ("localhost", true),
            ("127.0.0.1", true),
            ("::1", true),
            ("10.0.0.5", false),
            ("signet.internal", false),
        ];
        for (host, want) in cases {
            assert_eq!(is_loopback_host(host), *want, "is_loopback_host({host:?})");
        }
    }

    #[test]
    fn admin_transport_decision_loopback_defaults_to_plaintext() {
        let decision = admin_transport_decision("localhost:8444", None, false, false).unwrap();
        assert!(!decision.requires_tls());
    }

    #[test]
    fn admin_transport_decision_non_loopback_requires_tls() {
        let decision =
            admin_transport_decision("signet.internal:8444", None, false, false).unwrap();
        assert!(decision.requires_tls());
    }

    #[test]
    fn admin_transport_decision_force_tls_on_loopback() {
        let decision = admin_transport_decision("localhost:8444", None, true, false).unwrap();
        assert!(decision.requires_tls());
    }

    #[test]
    fn admin_transport_decision_plaintext_overrides_non_loopback() {
        // The whole point of issue #32: a non-loopback address (e.g. an
        // in-cluster Service DNS name) that would otherwise be upgraded to
        // TLS by the loopback heuristic stays plaintext when explicitly
        // requested.
        let decision =
            admin_transport_decision("signet.internal:8444", None, false, true).unwrap();
        assert!(!decision.requires_tls());
    }

    #[test]
    fn admin_transport_decision_plaintext_leaves_loopback_unaffected() {
        // plaintext on an address that would already default to plaintext
        // is a no-op, not an error.
        let decision = admin_transport_decision("localhost:8444", None, false, true).unwrap();
        assert!(!decision.requires_tls());
    }

    #[test]
    fn admin_transport_decision_rejects_force_tls_and_plaintext_together() {
        let err = admin_transport_decision("localhost:8444", None, true, true).unwrap_err();
        assert!(
            matches!(err, ClientError::ForceTlsPlaintextConflict),
            "expected ClientError::ForceTlsPlaintextConflict, got {err:?}"
        );
        assert_eq!(
            err.to_string(),
            "force_tls and plaintext are mutually exclusive"
        );
    }

    #[test]
    fn admin_transport_decision_rejects_plaintext_with_ca_pem() {
        let pem = b"-----BEGIN CERTIFICATE-----\nnot validated at this layer\n-----END CERTIFICATE-----\n";
        let err = admin_transport_decision("localhost:8444", Some(pem), false, true).unwrap_err();
        assert!(
            matches!(err, ClientError::PlaintextCaPemConflict),
            "expected ClientError::PlaintextCaPemConflict, got {err:?}"
        );
        assert_eq!(
            err.to_string(),
            "plaintext and ca_pem are mutually exclusive"
        );
    }

    #[test]
    fn admin_transport_decision_plaintext_with_empty_ca_pem_is_not_a_conflict() {
        // An empty (zero-length) CA slice is treated the same as `None`
        // throughout this module (see `ca_pem_non_empty` in
        // `admin_transport_decision`), so it doesn't trip the
        // plaintext/ca_pem mutual-exclusion check.
        let decision = admin_transport_decision("localhost:8444", Some(&[]), false, true).unwrap();
        assert!(!decision.requires_tls());
    }

    #[test]
    fn admin_transport_decision_ca_pem_forces_tls_even_on_loopback() {
        // Providing a CA bundle is a signal the caller wants TLS, even
        // against a loopback address (e.g. testing against a local TLS
        // listener via port-forward). This is a throwaway self-signed test
        // certificate (`openssl req -x509 -newkey rsa:2048 ...`), valid PEM
        // framing/DER but not chained to any real CA.
        let pem = b"-----BEGIN CERTIFICATE-----\n\
MIICoDCCAYgCCQDLsJN6ayvwqTANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAd0\n\
ZXN0LWNhMB4XDTI2MDcxMjIxMzM1MFoXDTI2MDcxMzIxMzM1MFowEjEQMA4GA1UE\n\
AwwHdGVzdC1jYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALKQT/9e\n\
HkJlnufQ8dCzc0JdZRO1gHDMY6stgfZljK1dEj2SaANpP3MDVIyDcmKq/6Gwbj4K\n\
fexqB+1VGLn7CKmopYBvAIwiMDHsQ/R8xDOLwVJRCwnxzAbUUsBF9LvRkDqV4U0/\n\
i7jizdwtxDHLoB9qEkDKWo3flgIGQtgJ6Vsj7YM9CPq369fby5ZBsPCR3itvEsiZ\n\
BoM13D3A2RFywYWFpvAvzlzR6LoFd4OnH/8QMh9KTTtxNYw2K8C/a2Cv3GZRROhN\n\
g5vcQbXLSyYVBUSwdEBT50/pl97KLStN54XEE2YQvoBZCU/kUBrOP888wn+ljafk\n\
XEMVrZiAKRDnZokCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAQpRqAdDsxNm+1qFf\n\
3IW8jJnfMrwdIUukE4c/ms7v3+n6QkdQYidfnZSXCrd0TAzXkRGonrFUDWAfRoGX\n\
ty0EN/hiU/wmDEvmsNgg9PS5KW3qqoIFRGYdwxn97hjJ0GdgUrbBLg0BweeaP+WW\n\
0Q7Jive55TT4W+Hwl5KETWOGi2FnvrlrDQGHWY1XKQKQn9J/tEQDMd+COyM9BHez\n\
oWg4npa5Q/5SdfJs3i4GyGRU4NWYxGfgFi7JiHOZx8t2Nv0RJkYqQu1SMNq97IDo\n\
ezQtmgLYbjPG41WWrdNT76h1mJgtlCzH0DfI7lQTBIi9AuE5poxPQiBoaC7flMsV\n\
w8cAzA==\n\
-----END CERTIFICATE-----\n";
        let decision = admin_transport_decision("localhost:8444", Some(pem), false, false);
        assert!(decision.is_ok());
        assert!(decision.unwrap().requires_tls());
    }

    #[test]
    fn admin_transport_decision_rejects_invalid_ca_pem() {
        let err =
            admin_transport_decision("signet.internal:8444", Some(b"not a cert"), false, false)
                .unwrap_err();
        assert!(
            matches!(err, ClientError::InvalidCaPem),
            "expected ClientError::InvalidCaPem, got {err:?}"
        );
        assert_eq!(err.to_string(), "invalid CA PEM bundle: no certificates found");
    }

    #[tokio::test]
    async fn dial_admin_rejects_empty_token() {
        let err = dial_admin("localhost:8444", "   ", None, false, false)
            .await
            .unwrap_err();
        assert!(matches!(err, ClientError::EmptyToken));
        assert_eq!(err.to_string(), "token must not be empty");
    }

    #[tokio::test]
    async fn gitops_client_and_admin_client_accept_both_channel_kinds() {
        // gitops_client/admin_client must accept both the AdminChannel
        // dial_admin returns (Channel + TokenInterceptor) and the plain
        // Channel dial_workload returns — that's the whole point of making
        // them generic. `Endpoint::connect_lazy` builds a real Channel
        // without touching the network (it only dials on first RPC), so
        // this actually constructs both client types over both channel
        // kinds rather than merely type-checking that it's possible.
        let plain_channel: Channel = Endpoint::from_static("http://localhost:1").connect_lazy();
        let _gitops_over_plain_channel = gitops_client(plain_channel.clone());
        let _admin_over_plain_channel = admin_client(plain_channel);

        let header_value: tonic::metadata::MetadataValue<tonic::metadata::Ascii> =
            "Bearer test-token".parse().unwrap();
        let admin_channel: AdminChannel = InterceptedService::new(
            Endpoint::from_static("http://localhost:1").connect_lazy(),
            TokenInterceptor { header_value },
        );
        let _gitops_over_admin_channel = gitops_client(admin_channel.clone());
        let _admin_over_admin_channel = admin_client(admin_channel);
    }

    #[test]
    fn host_of_handles_bracketed_ipv6_and_bare_hosts() {
        assert_eq!(host_of("localhost:8444"), "localhost");
        assert_eq!(host_of("127.0.0.1:8444"), "127.0.0.1");
        assert_eq!(host_of("[::1]:8444"), "::1");
        assert_eq!(host_of("signet.internal"), "signet.internal");
    }
}
