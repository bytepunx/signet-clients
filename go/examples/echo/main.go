// Command echo is a smoke-test fixture for the Docker/Kubernetes harness in
// bytepunx/signet-smoke-test. It exercises the same real code path a real
// service would: connect over SPIFFE mTLS, fetch a service bundle, and
// coordinate a fleet-wide-safe restart when signet reports a change — but,
// unlike a real service, it prints the fetched bundle (secrets included, in
// plaintext) to stdout so an out-of-band verification script can grep
// container logs and confirm the client library actually round-tripped real
// data through a real signet + SPIRE deployment, not just the hand-written
// fakes the unit test suites use.
//
// It is entirely configured via environment variables (no CLI flags), since
// it only ever runs as a container in Kubernetes:
//
//	SIGNET_ADDR              signet workload gRPC address (required)
//	SIGNET_TRUST_DOMAIN      SPIFFE trust domain (required)
//	SPIFFE_WORKLOAD_SOCKET   SPIFFE Workload API socket, as a unix:// URI (required)
//	SIGNET_NAMESPACE         signet namespace to fetch (required)
//	SIGNET_SERVICE           signet service to fetch (required)
//	SIGNET_SHARED_NAMESPACE  a second namespace to fetch, e.g. one only
//	                         reachable via an access policy rather than the
//	                         namespace/service convention (optional; must be
//	                         set together with SIGNET_SHARED_SERVICE)
//	SIGNET_SHARED_SERVICE    the service half of the pair above (optional)
//	RESTART_LOCK_TTL_SECONDS restart lock TTL in seconds (optional, default 30)
//	RESTART_DEBOUNCE_SECONDS restart debounce in seconds (optional, default 5)
//
// Sequence: fetch and print the bundle, then block in WaitForRestart until
// signet reports a change and this replica acquires the restart lock, then
// release the lock and exit 0. Kubernetes (restartPolicy: Always) starts a
// fresh container, which repeats the whole sequence against whatever
// changed — that loop is the actual behavior this harness exists to prove.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	signet "github.com/bytepunx/signet-clients/go"
	signetv1 "github.com/bytepunx/signet-clients/go/gen/signet/v1"
)

// testOnlyBanner is printed verbatim, unconditionally, as the very first
// thing this program does. This container's whole purpose is to leak
// secrets into its own logs for verification, so that must be impossible to
// miss.
const testOnlyBanner = "TEST-ONLY BUILD — DO NOT RUN IN PRODUCTION. This program prints retrieved secrets to stdout."

const (
	defaultLockTTLSeconds  = 30
	defaultDebounceSeconds = 5
)

func main() {
	fmt.Println(testOnlyBanner)

	addr := requireEnv("SIGNET_ADDR")
	trustDomain := requireEnv("SIGNET_TRUST_DOMAIN")
	socket := requireEnv("SPIFFE_WORKLOAD_SOCKET")
	namespace := requireEnv("SIGNET_NAMESPACE")
	service := requireEnv("SIGNET_SERVICE")
	sharedNamespace := os.Getenv("SIGNET_SHARED_NAMESPACE")
	sharedService := os.Getenv("SIGNET_SHARED_SERVICE")
	lockTTL := time.Duration(envIntOrDefault("RESTART_LOCK_TTL_SECONDS", defaultLockTTLSeconds)) * time.Second
	debounce := time.Duration(envIntOrDefault("RESTART_DEBOUNCE_SECONDS", defaultDebounceSeconds)) * time.Second

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	conn, closer, err := signet.DialWorkload(ctx, addr, socket, trustDomain)
	if err != nil {
		exitIfShuttingDown(ctx, "dial")
		log.Fatalf("DialWorkload: %v", err)
	}
	defer conn.Close()
	defer closer() //nolint:errcheck

	client := signet.SecretsClient(conn)

	bundle, err := client.GetServiceBundle(ctx, &signetv1.GetServiceBundleRequest{
		Namespace: namespace,
		Service:   service,
	})
	if err != nil {
		exitIfShuttingDown(ctx, "GetServiceBundle")
		log.Fatalf("GetServiceBundle: %v", err)
	}

	line, err := echoBundleLine(bundle)
	if err != nil {
		log.Fatalf("decode bundle: %v", err)
	}
	fmt.Println("ECHO_BUNDLE: " + line)

	// Optional second fetch proving cross-namespace access via an admin-
	// granted policy actually works, not just the namespace/service
	// convention — most workloads never need this (see signet's
	// docs/policies.md), but the smoke-test harness sets these two env
	// vars specifically to exercise that path end to end.
	if sharedNamespace != "" && sharedService != "" {
		sharedBundle, err := client.GetServiceBundle(ctx, &signetv1.GetServiceBundleRequest{
			Namespace: sharedNamespace,
			Service:   sharedService,
		})
		if err != nil {
			log.Fatalf("GetServiceBundle (shared): %v", err)
		}
		sharedLine, err := echoBundleLine(sharedBundle)
		if err != nil {
			log.Fatalf("decode shared bundle: %v", err)
		}
		fmt.Println("ECHO_SHARED_BUNDLE: " + sharedLine)
	}

	// Block until signet reports a change and this replica holds the
	// fleet-wide restart lock — the steady-state behavior while nothing has
	// changed is to block here, potentially indefinitely.
	lock, err := signet.WaitForRestart(ctx, client, namespace, service, lockTTL, debounce)
	if err != nil {
		exitIfShuttingDown(ctx, "WaitForRestart")
		log.Fatalf("WaitForRestart: %v", err)
	}

	restartLine, err := json.Marshal(map[string]any{
		"token":      lock.Token(),
		"expires_at": lock.ExpiresAt().UTC().Format(time.RFC3339),
	})
	if err != nil {
		log.Fatalf("marshal restart line: %v", err)
	}
	fmt.Println("ECHO_RESTART: " + string(restartLine))

	if err := lock.Release(); err != nil {
		slog.Warn("lock release failed (it will still expire via TTL)", "err", err)
	}
	os.Exit(0)
}

// requireEnv reads name from the environment, failing fast with a specific,
// unambiguous error if it is unset or blank. This container's only
// observable output is its logs, so a vague error here would be expensive
// to debug against a real cluster.
func requireEnv(name string) string {
	v, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(v) == "" {
		log.Fatalf("missing required environment variable %s", name)
	}
	return v
}

// envIntOrDefault reads name from the environment as an integer, returning
// def if it is unset or fails to parse.
func envIntOrDefault(name string, def int) int {
	v, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		slog.Warn("invalid integer env var, using default", "var", name, "value", v, "default", def)
		return def
	}
	return n
}

// exitIfShuttingDown logs and exits 0 if ctx has already been canceled
// (SIGTERM/SIGINT), so a shutdown signal arriving during a blocking call
// is treated as ordinary termination rather than a fatal error. op names
// the operation that was interrupted, for logging only.
func exitIfShuttingDown(ctx context.Context, op string) {
	if ctx.Err() != nil {
		slog.Info("shutting down", "during", op, "reason", ctx.Err())
		os.Exit(0)
	}
}

// echoBundleLine renders resp as a single-line JSON object: bundle config
// fields at the top level, config_version alongside them, and secrets
// base64-decoded to plaintext under a "secrets" key — so a verification
// script can grep the ECHO_BUNDLE: line and parse plaintext secret values
// directly, matching what signet's own workload API actually returned
// rather than the base64 wire encoding.
func echoBundleLine(resp *signetv1.GetServiceBundleResponse) (string, error) {
	out := resp.GetBundle().AsMap()

	if rawSecrets, ok := out["secrets"]; ok {
		secretsMap, ok := rawSecrets.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("bundle \"secrets\" field is %T, not an object", rawSecrets)
		}
		decoded := make(map[string]interface{}, len(secretsMap))
		for name, v := range secretsMap {
			s, ok := v.(string)
			if !ok {
				return "", fmt.Errorf("secret %q value is %T, not a string", name, v)
			}
			plain, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				return "", fmt.Errorf("base64-decode secret %q: %w", name, err)
			}
			decoded[name] = string(plain)
		}
		out["secrets"] = decoded
	}
	out["config_version"] = resp.GetConfigVersion()

	b, err := json.Marshal(out)
	if err != nil {
		return "", fmt.Errorf("marshal bundle: %w", err)
	}
	return string(b), nil
}
