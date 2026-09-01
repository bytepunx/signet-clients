// Package signet provides connection helpers for talking to a signet server.
//
// Two connection modes mirror the two listeners signet exposes:
//   - DialWorkload connects to the workload-facing SecretsService using SPIFFE
//     mTLS, the same credential mechanism the signet server itself uses to
//     authenticate callers. It retries automatically, with no opt-in
//     required, if it loses the SPIRE identity-registration-propagation
//     race described in its doc comment.
//   - DialAdmin connects to the operator-facing AdminService/GitOpsService
//     using a bearer token over TLS (or plaintext for loopback addresses, or
//     for any address when explicitly requested via the plaintext
//     parameter), mirroring signet's own `signet` CLI.
package signet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	adminv1 "github.com/bytepunx/signet-clients/go/gen/admin/v1"
	signetv1 "github.com/bytepunx/signet-clients/go/gen/signet/v1"
	grpccredentials "github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// workloadDialBackoff is the wait before each retry DialWorkload makes
// after the Workload API reports "no identity issued" (see DialWorkload's
// doc comment): 1s, 2s, 4s, 8s — exponential, doubling each time and capped
// at 8s. This is the exact schedule verified working in a real downstream
// consumer that hit this race (bytepunx/signet-clients#33 —
// bytepunx/kluster's RabbitMQ credential-provisioning Job, which retries
// its own dial 5 times total with this identical backoff), so
// len(workloadDialBackoff) retries are made beyond the initial attempt —
// workloadDialMaxAttempts total — with a worst case of roughly 15s of
// sleeping before DialWorkload gives up.
var workloadDialBackoff = [4]time.Duration{
	1 * time.Second,
	2 * time.Second,
	4 * time.Second,
	8 * time.Second,
}

// workloadDialMaxAttempts is the total number of identity-readiness probes
// DialWorkload makes (the initial attempt plus len(workloadDialBackoff)
// retries) before giving up.
const workloadDialMaxAttempts = len(workloadDialBackoff) + 1

// DialWorkload opens a gRPC connection to signet's workload listener,
// authenticating via SPIFFE mTLS. socketPath is the SPIFFE Workload API
// socket (e.g. "unix:///run/spire/sockets/agent.sock"); trustDomain must
// match the trust domain of the target signet instance. The returned closer
// must be closed alongside the connection to release the X509Source.
//
// The returned conn is a plain *grpc.ClientConn — pass it to SecretsClient
// for the workload-facing SecretsService, or to GitOpsClient for the subset
// of GitOpsService reachable this way (SyncBundle, PatchServiceConfig,
// GetSOPSPublicKey) without needing an admin bearer token at all. See
// GitOpsClient's doc comment and examples/gitops-workload.
//
// DialWorkload retries automatically — no opt-in required — if the
// Workload API reports "no identity issued" (a PermissionDenied status)
// before it can hand back a connection. This is a real,
// verified-in-production race, not speculative hardening: SPIRE's
// controller-manager reconciles a brand-new pod's SPIFFE identity
// registration reactively, off the pod's own creation event, and that
// registration takes a few seconds to propagate from there to the
// node-local SPIRE agent this dials over socketPath. A freshly-created
// pod's very first DialWorkload call — a Job's is the sharpest case, since
// a Job has no prior pod that might have already won this race for the
// same ServiceAccount — can lose it outright and see "no identity issued"
// even though the identity shows up moments later. See
// bytepunx/signet-clients#33 for the full writeup, including where this was
// first hit (bytepunx/kluster's RabbitMQ credential-provisioning Job).
//
// The retry makes up to workloadDialMaxAttempts (5) attempts total — the
// initial attempt plus up to 4 retries — backing off per
// workloadDialBackoff (1s, 2s, 4s, 8s) between them. Only the "no
// identity issued" failure is retried: every other error (a bad
// socketPath, an expired or canceled ctx, a malformed trustDomain, a
// genuine authorization problem once identity issuance is actually broken
// rather than merely delayed, ...) is returned to the caller immediately,
// unretried, so this never masks a real misconfiguration as a transient
// blip.
func DialWorkload(ctx context.Context, addr, socketPath, trustDomain string) (conn *grpc.ClientConn, closer func() error, err error) {
	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid trust domain %q: %w", trustDomain, err)
	}

	addrOpt := workloadapi.WithAddr(socketPath)

	// Probe with a single-shot, non-watching fetch first. workloadapi's
	// watch-based APIs (which NewX509Source uses internally) already retry
	// "no identity issued" forever with their own uncontrollable, unbounded
	// linear backoff, silently absorbing the very error we need to see and
	// pace ourselves — so we can't classify or bound retries by calling
	// NewX509Source directly in this loop. A plain FetchX509Context call has
	// no such internal retry: it surfaces the raw status on every attempt,
	// which is exactly what retryUntilIdentityIssued needs to classify and
	// pace deliberately per workloadDialBackoff.
	probe := func(ctx context.Context) error {
		_, err := workloadapi.FetchX509Context(ctx, addrOpt)
		return err
	}
	if err := retryUntilIdentityIssued(ctx, probe, sleepOrDone); err != nil {
		return nil, nil, fmt.Errorf("connect to SPIFFE workload API at %s: %w", socketPath, err)
	}

	// The identity is confirmed issued, so this establishes near-instantly
	// in the common case; NewX509Source's own internal retry remains as a
	// safety net for any further transient hiccup, but the race this
	// function exists to close has already been won above.
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(addrOpt))
	if err != nil {
		return nil, nil, fmt.Errorf("connect to SPIFFE workload API at %s: %w", socketPath, err)
	}

	creds := grpccredentials.MTLSClientCredentials(source, source, tlsconfig.AuthorizeMemberOf(td))
	conn, err = grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		source.Close() //nolint:errcheck
		return nil, nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	return conn, source.Close, nil
}

// retryUntilIdentityIssued calls probe, retrying per workloadDialBackoff
// (via sleep, so tests can substitute a non-blocking fake — see
// sleepOrDone) as long as probe keeps failing with isNoIdentityIssuedErr.
// It returns nil as soon as probe succeeds, the first error probe returns
// that isn't a "no identity issued" failure, or a wrapped error naming the
// last "no identity issued" failure once workloadDialMaxAttempts is
// exhausted. If sleep reports ctx is done, ctx.Err() is returned.
func retryUntilIdentityIssued(ctx context.Context, probe func(context.Context) error, sleep func(context.Context, time.Duration) bool) error {
	var lastErr error
	for attempt := 0; attempt < workloadDialMaxAttempts; attempt++ {
		lastErr = probe(ctx)
		if lastErr == nil {
			return nil
		}
		if !isNoIdentityIssuedErr(lastErr) {
			return lastErr
		}
		if attempt == len(workloadDialBackoff) {
			break
		}
		if !sleep(ctx, workloadDialBackoff[attempt]) {
			return ctx.Err()
		}
	}
	return fmt.Errorf("no identity issued after %d attempts: %w", workloadDialMaxAttempts, lastErr)
}

// isNoIdentityIssuedErr reports whether err is the SPIFFE Workload API's
// "no identity issued" failure: a PermissionDenied status returned by
// FetchX509SVID (and so also by FetchX509Context, which wraps it) when the
// calling workload has no SPIFFE identity registered yet — the exact
// condition documented on DialWorkload that its retry exists for. Matching
// is deliberately on status code alone, not error text, since the code is
// the stable part of this contract across SPIRE versions.
func isNoIdentityIssuedErr(err error) bool {
	return status.Code(err) == codes.PermissionDenied
}

// SecretsClient returns a SecretsService client bound to conn.
func SecretsClient(conn *grpc.ClientConn) signetv1.SecretsServiceClient {
	return signetv1.NewSecretsServiceClient(conn)
}

// DialAdmin opens a gRPC connection to signet's admin listener, injecting
// token into every RPC as a bearer credential.
//
// Transport security is chosen automatically from addr:
//   - Loopback addresses (localhost, 127.0.0.1, ::1 — the documented
//     `kubectl port-forward` workflow) default to plaintext.
//   - Every other address is upgraded to TLS automatically, using the
//     system trust store, or the CA in caPEM if provided.
//
// forceTLS and plaintext both override that heuristic, in opposite
// directions:
//   - forceTLS requests TLS even for a loopback address (e.g. testing a
//     real TLS-terminating proxy locally).
//   - plaintext forces insecure transport credentials even for a
//     non-loopback address, bypassing the loopback heuristic entirely.
//     This is required once signet exposes a real in-cluster admin
//     listener (bytepunx/signet#19): dialing that Service by its
//     cluster-DNS name is a non-loopback address, but the listener is
//     intentionally still plaintext-behind-bearer-token, not
//     TLS-terminated — without plaintext, the loopback heuristic would
//     pick TLS and the handshake would fail immediately ("wrong version
//     number") against a server that never speaks TLS on that listener.
//     See bytepunx/signet-clients#32.
//
// Per-RPC bearer-token authentication (the actual mechanism signet uses to
// authenticate the caller) is unaffected either way — plaintext only
// changes the transport, never who signet trusts the caller to be.
//
// forceTLS and plaintext are mutually exclusive with each other, and
// plaintext is mutually exclusive with a non-empty caPEM (there is no
// meaningful CA to verify against when the transport isn't TLS at all);
// DialAdmin returns an error if either combination is requested.
func DialAdmin(addr, token string, caPEM []byte, forceTLS, plaintext bool) (*grpc.ClientConn, error) {
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("token must not be empty")
	}

	creds, requireTLS, err := adminTransportCreds(addr, caPEM, forceTLS, plaintext)
	if err != nil {
		return nil, err
	}

	return grpc.NewClient(addr,
		grpc.WithTransportCredentials(creds),
		grpc.WithPerRPCCredentials(tokenCreds{token: strings.TrimSpace(token), requireTLS: requireTLS}),
	)
}

// AdminClient returns an AdminService client bound to conn.
func AdminClient(conn *grpc.ClientConn) adminv1.AdminServiceClient {
	return adminv1.NewAdminServiceClient(conn)
}

// GitOpsClient returns a GitOpsService client bound to conn. conn may come
// from either DialAdmin (bearer-token auth, full access) or DialWorkload
// (SPIFFE mTLS, the caller's own identity) — signet's server accepts both
// for SyncBundle, PatchServiceConfig, and GetSOPSPublicKey, letting a
// workload self-service its own bundle/config writes and fetch the active
// SOPS public key without ever holding an admin token (bytepunx/signet#23,
// #38, #78). See examples/gitops-workload for a runnable demonstration.
func GitOpsClient(conn *grpc.ClientConn) adminv1.GitOpsServiceClient {
	return adminv1.NewGitOpsServiceClient(conn)
}

func adminTransportCreds(addr string, caPEM []byte, forceTLS, plaintext bool) (creds credentials.TransportCredentials, requireTLS bool, err error) {
	if plaintext && forceTLS {
		return nil, false, fmt.Errorf("forceTLS and plaintext are mutually exclusive")
	}
	if plaintext && len(caPEM) > 0 {
		return nil, false, fmt.Errorf("plaintext and caPEM are mutually exclusive")
	}
	if plaintext {
		return insecure.NewCredentials(), false, nil
	}

	host := addr
	if h, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
		host = h
	}

	useTLS := forceTLS || len(caPEM) > 0 || !isLoopbackHost(host)
	if !useTLS {
		return insecure.NewCredentials(), false, nil
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, false, fmt.Errorf("no PEM certificates found in provided CA bundle")
		}
		tlsCfg.RootCAs = pool
	}
	return credentials.NewTLS(tlsCfg), true, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// tokenCreds injects Authorization: Bearer <token> into every outgoing RPC.
type tokenCreds struct {
	token      string
	requireTLS bool
}

func (c tokenCreds) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + c.token}, nil
}

func (c tokenCreds) RequireTransportSecurity() bool { return c.requireTLS }

// ReadCAFile reads a PEM CA bundle from path for use with DialAdmin.
func ReadCAFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
