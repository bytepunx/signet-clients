// Command gitops-workload demonstrates calling GitOpsService over a
// workload's own SPIFFE mTLS identity instead of an admin bearer token.
//
// DialWorkload returns a plain *grpc.ClientConn — the same one SecretsClient
// binds to secretsclient/examples/getsecret — so GitOpsClient(conn) works
// exactly the same way. This is the self-service path signet's server
// already supports for SyncBundle, PatchServiceConfig, and GetSOPSPublicKey
// (bytepunx/signet#23, #38, #78): a workload can push its own bundle, patch
// its own config, or fetch signet's active SOPS public key using nothing
// but its own workload identity, with no admin token in the picture at all.
// Cross-namespace/service writes still require an explicit CreatePolicy
// grant from an operator — see the design doc's "Self-service workload
// pushes" section.
//
// This example calls GetSOPSPublicKey specifically because it needs no
// setup (no bundle to build, no JSON Patch to construct) — SyncBundle and
// PatchServiceConfig are reachable the identical way, just swap the client
// method called below.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	signet "github.com/bytepunx/signet-clients/go"
	adminv1 "github.com/bytepunx/signet-clients/go/gen/admin/v1"
)

func main() {
	addr := flag.String("addr", "localhost:8443", "signet workload gRPC address")
	socket := flag.String("socket", "unix:///run/spire/sockets/agent.sock", "SPIFFE Workload API socket")
	trustDomain := flag.String("trust-domain", "example.org", "expected SPIFFE trust domain")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, closer, err := signet.DialWorkload(ctx, *addr, *socket, *trustDomain)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	defer closer() //nolint:errcheck

	// GitOpsClient accepts any *grpc.ClientConn, including one built by
	// DialWorkload for the SecretsService client above — no separate dial
	// mode is needed.
	client := signet.GitOpsClient(conn)
	resp, err := client.GetSOPSPublicKey(ctx, &adminv1.GetSOPSPublicKeyRequest{})
	if err != nil {
		log.Fatalf("GetSOPSPublicKey: %v", err)
	}
	fmt.Printf("public_key=%s fingerprint=%s environment=%q\n", resp.PublicKey, resp.Fingerprint, resp.Environment)
}
