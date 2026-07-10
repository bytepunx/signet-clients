// Command restart-on-change demonstrates the intended pattern for a service
// that pulls its own signet configuration directly, in-memory, and
// coordinates a safe restart when that configuration changes — without a
// process host (kickr) and without ever writing secrets to its environment.
//
// The pattern:
//  1. Fetch the bundle once at startup and configure the app in memory.
//  2. Serve traffic normally.
//  3. Block on WaitForRestart, which only returns once signet reports a
//     change AND this replica has acquired the distributed restart lock —
//     guaranteeing at most one replica restarts at a time fleet-wide.
//  4. Do your own graceful shutdown (drain in-flight requests, close
//     resources).
//  5. Release the lock, then exit 0. Kubernetes starts a fresh process,
//     which repeats from step 1 with the new configuration.
package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	signet "github.com/bytepunx/signet-clients/go"
	signetv1 "github.com/bytepunx/signet-clients/go/gen/signet/v1"
)

func main() {
	addr := flag.String("addr", "localhost:8443", "signet workload gRPC address")
	socket := flag.String("socket", "unix:///run/spire/sockets/agent.sock", "SPIFFE Workload API socket")
	trustDomain := flag.String("trust-domain", "example.org", "expected SPIFFE trust domain")
	namespace := flag.String("namespace", "default", "bundle/lock namespace")
	service := flag.String("service", "example", "bundle/lock service")
	lockTTL := flag.Duration("lock-ttl", 30*time.Second, "restart lock TTL — must cover your graceful shutdown time")
	debounce := flag.Duration("debounce", 10*time.Second, "wait this long after a change before acting, to absorb rapid successive edits")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	conn, closer, err := signet.DialWorkload(ctx, *addr, *socket, *trustDomain)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	defer closer() //nolint:errcheck

	client := signet.SecretsClient(conn)

	// 1. Fetch once at startup; configure the app in memory. Never write
	// this to the environment or disk.
	bundle, err := client.GetServiceBundle(ctx, &signetv1.GetServiceBundleRequest{
		Namespace: *namespace,
		Service:   *service,
	})
	if err != nil {
		log.Fatalf("GetServiceBundle: %v", err)
	}
	slog.Info("configured", "config_version", bundle.ConfigVersion)

	// 2. Serve traffic normally (omitted — this is a minimal example).

	// 3. Block until a change is reported and this replica holds the lock.
	lock, err := signet.WaitForRestart(ctx, client, *namespace, *service, *lockTTL, *debounce)
	if err != nil {
		if ctx.Err() != nil {
			// SIGTERM/SIGINT arrived before any change did — ordinary shutdown.
			slog.Info("shutting down", "reason", ctx.Err())
			os.Exit(0)
		}
		log.Fatalf("WaitForRestart: %v", err)
	}
	slog.Info("restart lock acquired", "token", lock.Token(), "expires_at", lock.ExpiresAt())

	// 4. Graceful shutdown: drain in-flight requests, close resources.
	// (omitted — this is a minimal example).

	// 5. Release the lock for the next waiting replica, then exit 0.
	// Kubernetes restarts the pod; the new process fetches the bundle fresh.
	if err := lock.Release(); err != nil {
		slog.Warn("lock release failed (it will still expire via TTL)", "err", err)
	}
	os.Exit(0)
}
