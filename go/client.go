// Package signet provides connection helpers for talking to a signet server.
//
// Two connection modes mirror the two listeners signet exposes:
//   - DialWorkload connects to the workload-facing SecretsService using SPIFFE
//     mTLS, the same credential mechanism the signet server itself uses to
//     authenticate callers.
//   - DialAdmin connects to the operator-facing AdminService/GitOpsService
//     using a bearer token over TLS (or plaintext for loopback addresses),
//     mirroring signet's own `signet` CLI.
package signet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"

	adminv1 "github.com/bytepunx/signet-clients/go/gen/admin/v1"
	signetv1 "github.com/bytepunx/signet-clients/go/gen/signet/v1"
	grpccredentials "github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// DialWorkload opens a gRPC connection to signet's workload listener,
// authenticating via SPIFFE mTLS. socketPath is the SPIFFE Workload API
// socket (e.g. "unix:///run/spire/sockets/agent.sock"); trustDomain must
// match the trust domain of the target signet instance. The returned closer
// must be closed alongside the connection to release the X509Source.
func DialWorkload(ctx context.Context, addr, socketPath, trustDomain string) (conn *grpc.ClientConn, closer func() error, err error) {
	source, err := workloadapi.NewX509Source(ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to SPIFFE workload API at %s: %w", socketPath, err)
	}

	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		source.Close() //nolint:errcheck
		return nil, nil, fmt.Errorf("invalid trust domain %q: %w", trustDomain, err)
	}

	creds := grpccredentials.MTLSClientCredentials(source, source, tlsconfig.AuthorizeMemberOf(td))
	conn, err = grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		source.Close() //nolint:errcheck
		return nil, nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	return conn, source.Close, nil
}

// SecretsClient returns a SecretsService client bound to conn.
func SecretsClient(conn *grpc.ClientConn) signetv1.SecretsServiceClient {
	return signetv1.NewSecretsServiceClient(conn)
}

// DialAdmin opens a gRPC connection to signet's admin listener, injecting
// token into every RPC as a bearer credential. Loopback addresses (the
// documented `kubectl port-forward` workflow) use plaintext by default;
// every other address is upgraded to TLS automatically using the system
// trust store, or the CA in caPEM if provided. forceTLS requests TLS even
// for a loopback address.
func DialAdmin(addr, token string, caPEM []byte, forceTLS bool) (*grpc.ClientConn, error) {
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("token must not be empty")
	}

	creds, requireTLS, err := adminTransportCreds(addr, caPEM, forceTLS)
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

// GitOpsClient returns a GitOpsService client bound to conn.
func GitOpsClient(conn *grpc.ClientConn) adminv1.GitOpsServiceClient {
	return adminv1.NewGitOpsServiceClient(conn)
}

func adminTransportCreds(addr string, caPEM []byte, forceTLS bool) (creds credentials.TransportCredentials, requireTLS bool, err error) {
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
