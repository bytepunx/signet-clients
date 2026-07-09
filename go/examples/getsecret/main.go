// Command getsecret is a minimal example of using the signet Go client to
// fetch a secret over SPIFFE mTLS.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	signet "github.com/bytepunx/signet-clients/go"
	signetv1 "github.com/bytepunx/signet-clients/go/gen/signet/v1"
)

func main() {
	addr := flag.String("addr", "localhost:8443", "signet workload gRPC address")
	socket := flag.String("socket", "unix:///run/spire/sockets/agent.sock", "SPIFFE Workload API socket")
	trustDomain := flag.String("trust-domain", "example.org", "expected SPIFFE trust domain")
	namespace := flag.String("namespace", "default", "secret namespace")
	service := flag.String("service", "example", "secret service")
	name := flag.String("name", "api-key", "secret name")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, closer, err := signet.DialWorkload(ctx, *addr, *socket, *trustDomain)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	defer closer() //nolint:errcheck

	client := signet.SecretsClient(conn)
	resp, err := client.GetSecret(ctx, &signetv1.GetSecretRequest{
		Namespace: *namespace,
		Service:   *service,
		Name:      *name,
	})
	if err != nil {
		log.Fatalf("GetSecret: %v", err)
	}
	fmt.Printf("version=%d value=%q\n", resp.Version, resp.Value)
}
