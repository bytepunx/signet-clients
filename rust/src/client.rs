//! Connection helpers for talking to a signet server.
//!
//! Mirrors `go/client.go`: [`dial_admin`] opens a bearer-token connection to
//! the operator-facing `AdminService`/`GitOpsService` listener, applying the
//! same loopback-defaults-to-plaintext logic as the Go client and the
//! `signet` CLI. [`dial_workload`] (behind the `spiffe-workload` feature)
//! opens a SPIFFE-mTLS connection to the workload-facing `SecretsService`
//! listener.

use std::net::IpAddr;
use std::path::Path;

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
/// Loopback addresses (the documented `kubectl port-forward` workflow) use
/// plaintext by default; every other address is upgraded to TLS
/// automatically using the system trust store, or the CA in `ca_pem` if
/// provided. `force_tls` requests TLS even for a loopback address.
///
/// Returns [`ClientError::EmptyToken`] if `token` is empty or
/// whitespace-only, before any connection attempt is made.
pub async fn dial_admin(
    addr: impl AsRef<str>,
    token: impl AsRef<str>,
    ca_pem: Option<&[u8]>,
    force_tls: bool,
) -> Result<AdminChannel, ClientError> {
    let addr = addr.as_ref();
    let token = token.as_ref().trim();
    if token.is_empty() {
        return Err(ClientError::EmptyToken);
    }

    let decision = admin_transport_decision(addr, ca_pem, force_tls)?;
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
pub fn admin_client(channel: AdminChannel) -> AdminServiceClient<AdminChannel> {
    AdminServiceClient::new(channel)
}

/// Returns a `GitOpsService` client bound to `channel`.
pub fn gitops_client(channel: AdminChannel) -> GitOpsServiceClient<AdminChannel> {
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
) -> Result<TransportDecision, ClientError> {
    let host = host_of(addr);
    let use_tls =
        force_tls || ca_pem.map(|pem| !pem.is_empty()).unwrap_or(false) || !is_loopback_host(&host);

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

    use tokio::net::TcpStream;
    use tonic::codegen::http::Uri;
    use tonic::codegen::Service;
    use tonic::transport::{Channel, Endpoint};

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

        let endpoint =
            Endpoint::from_shared(format!("https://{addr}")).map_err(|source| {
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
        let decision = admin_transport_decision("localhost:8444", None, false).unwrap();
        assert!(!decision.requires_tls());
    }

    #[test]
    fn admin_transport_decision_non_loopback_requires_tls() {
        let decision = admin_transport_decision("signet.internal:8444", None, false).unwrap();
        assert!(decision.requires_tls());
    }

    #[test]
    fn admin_transport_decision_force_tls_on_loopback() {
        let decision = admin_transport_decision("localhost:8444", None, true).unwrap();
        assert!(decision.requires_tls());
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
        let decision = admin_transport_decision("localhost:8444", Some(pem), false);
        assert!(decision.is_ok());
        assert!(decision.unwrap().requires_tls());
    }

    #[test]
    fn admin_transport_decision_rejects_invalid_ca_pem() {
        let err = admin_transport_decision("signet.internal:8444", Some(b"not a cert"), false)
            .unwrap_err();
        assert!(
            matches!(err, ClientError::InvalidCaPem),
            "expected ClientError::InvalidCaPem, got {err:?}"
        );
        assert_eq!(err.to_string(), "invalid CA PEM bundle: no certificates found");
    }

    #[tokio::test]
    async fn dial_admin_rejects_empty_token() {
        let err = dial_admin("localhost:8444", "   ", None, false)
            .await
            .unwrap_err();
        assert!(matches!(err, ClientError::EmptyToken));
        assert_eq!(err.to_string(), "token must not be empty");
    }

    #[test]
    fn host_of_handles_bracketed_ipv6_and_bare_hosts() {
        assert_eq!(host_of("localhost:8444"), "localhost");
        assert_eq!(host_of("127.0.0.1:8444"), "127.0.0.1");
        assert_eq!(host_of("[::1]:8444"), "::1");
        assert_eq!(host_of("signet.internal"), "signet.internal");
    }
}
