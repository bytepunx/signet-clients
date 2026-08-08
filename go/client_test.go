package signet

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIsLoopbackHost(t *testing.T) {
	cases := map[string]bool{
		"localhost":       true,
		"127.0.0.1":       true,
		"::1":             true,
		"10.0.0.5":        false,
		"signet.internal": false,
	}
	for host, want := range cases {
		if got := isLoopbackHost(host); got != want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestAdminTransportCreds_LoopbackDefaultsPlaintext(t *testing.T) {
	_, requireTLS, err := adminTransportCreds("localhost:8444", nil, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if requireTLS {
		t.Errorf("expected plaintext for loopback address without --tls")
	}
}

func TestAdminTransportCreds_NonLoopbackRequiresTLS(t *testing.T) {
	_, requireTLS, err := adminTransportCreds("signet.internal:8444", nil, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !requireTLS {
		t.Errorf("expected TLS to be required for a non-loopback address")
	}
}

func TestAdminTransportCreds_ForceTLSOnLoopback(t *testing.T) {
	_, requireTLS, err := adminTransportCreds("localhost:8444", nil, true, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !requireTLS {
		t.Errorf("expected TLS to be required when forceTLS is set")
	}
}

func TestAdminTransportCreds_InvalidCAPEM(t *testing.T) {
	_, _, err := adminTransportCreds("signet.internal:8444", []byte("not a cert"), false, false)
	if err == nil {
		t.Errorf("expected error for invalid CA PEM")
	}
}

// TestAdminTransportCreds_PlaintextOverridesNonLoopback covers
// bytepunx/signet-clients#32: a non-loopback address (the shape of an
// in-cluster Service DNS name) with plaintext=true must still get insecure
// transport credentials, bypassing the loopback heuristic entirely.
func TestAdminTransportCreds_PlaintextOverridesNonLoopback(t *testing.T) {
	creds, requireTLS, err := adminTransportCreds("signet.internal:8444", nil, false, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if requireTLS {
		t.Errorf("expected plaintext=true to force insecure transport for a non-loopback address")
	}
	if creds.Info().SecurityProtocol != "insecure" {
		t.Errorf("expected insecure transport credentials, got %q", creds.Info().SecurityProtocol)
	}
}

// TestAdminTransportCreds_PlaintextOnLoopbackIsStillPlaintext confirms the
// existing loopback-defaults-to-plaintext behavior is unchanged when
// plaintext is also explicitly set (a redundant but harmless combination).
func TestAdminTransportCreds_PlaintextOnLoopbackIsStillPlaintext(t *testing.T) {
	_, requireTLS, err := adminTransportCreds("localhost:8444", nil, false, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if requireTLS {
		t.Errorf("expected plaintext for loopback address with plaintext=true")
	}
}

func TestAdminTransportCreds_PlaintextAndForceTLSAreMutuallyExclusive(t *testing.T) {
	if _, _, err := adminTransportCreds("signet.internal:8444", nil, true, true); err == nil {
		t.Errorf("expected error when both forceTLS and plaintext are set")
	}
}

func TestAdminTransportCreds_PlaintextAndCAPEMAreMutuallyExclusive(t *testing.T) {
	if _, _, err := adminTransportCreds("signet.internal:8444", []byte("some pem"), false, true); err == nil {
		t.Errorf("expected error when both caPEM and plaintext are set")
	}
}

func TestDialAdmin_RejectsEmptyToken(t *testing.T) {
	if _, err := DialAdmin("localhost:8444", "  ", nil, false, false); err == nil {
		t.Errorf("expected error for empty token")
	}
}

// TestDialAdmin_PlaintextOnNonLoopbackSucceeds covers the DialAdmin-level
// entry point for #32: grpc.NewClient doesn't dial eagerly, so a
// non-loopback address with plaintext=true should construct successfully
// without ever attempting a real (and, pre-#32, TLS-handshake-failing)
// network connection.
func TestDialAdmin_PlaintextOnNonLoopbackSucceeds(t *testing.T) {
	conn, err := DialAdmin("signet.internal:8444", "token", nil, false, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer conn.Close()
}

// TestDialAdmin_ForceTLSAndPlaintextRejected ensures the contradictory
// combination is rejected at the DialAdmin entry point too, not just in
// the adminTransportCreds helper.
func TestDialAdmin_ForceTLSAndPlaintextRejected(t *testing.T) {
	if _, err := DialAdmin("localhost:8444", "token", nil, true, true); err == nil {
		t.Errorf("expected error when both forceTLS and plaintext are set")
	}
}

// --- DialWorkload retry (bytepunx/signet-clients#33) ---

// noIdentityIssuedErr builds the exact status the SPIFFE Workload API (and
// go-spiffe's own fakeworkloadapi test fixture) returns when the calling
// workload has no SPIFFE identity registered yet.
func noIdentityIssuedErr() error {
	return status.Error(codes.PermissionDenied, "no identity issued")
}

// fakeSleep records the durations retryUntilIdentityIssued asks it to
// wait, without actually blocking, so tests exercising the full
// workloadDialMaxAttempts schedule run in milliseconds, not ~23s.
type fakeSleep struct {
	waited []time.Duration
}

func (f *fakeSleep) sleep(_ context.Context, d time.Duration) bool {
	f.waited = append(f.waited, d)
	return true
}

func TestIsNoIdentityIssuedErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"permission denied no identity issued", noIdentityIssuedErr(), true},
		{"permission denied, different message", status.Error(codes.PermissionDenied, "go away"), true},
		{"unavailable", status.Error(codes.Unavailable, "connection refused"), false},
		{"invalid argument", status.Error(codes.InvalidArgument, "bad request"), false},
		{"plain error", errors.New("boom"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNoIdentityIssuedErr(tc.err); got != tc.want {
				t.Errorf("isNoIdentityIssuedErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestRetryUntilIdentityIssued_SucceedsFirstAttemptNoSleep(t *testing.T) {
	sleeper := &fakeSleep{}
	calls := 0
	probe := func(context.Context) error {
		calls++
		return nil
	}

	if err := retryUntilIdentityIssued(context.Background(), probe, sleeper.sleep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("probe called %d times, want 1", calls)
	}
	if len(sleeper.waited) != 0 {
		t.Errorf("expected no backoff sleeps on first-attempt success, got %v", sleeper.waited)
	}
}

func TestRetryUntilIdentityIssued_SucceedsAfterRetries(t *testing.T) {
	sleeper := &fakeSleep{}
	calls := 0
	probe := func(context.Context) error {
		calls++
		if calls < 3 {
			return noIdentityIssuedErr()
		}
		return nil
	}

	if err := retryUntilIdentityIssued(context.Background(), probe, sleeper.sleep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 3 {
		t.Errorf("probe called %d times, want 3", calls)
	}
	wantWaits := []time.Duration{1 * time.Second, 2 * time.Second}
	if len(sleeper.waited) != len(wantWaits) {
		t.Fatalf("waited %v, want %v", sleeper.waited, wantWaits)
	}
	for i, d := range wantWaits {
		if sleeper.waited[i] != d {
			t.Errorf("backoff[%d] = %v, want %v", i, sleeper.waited[i], d)
		}
	}
}

// TestRetryUntilIdentityIssued_ExhaustsAllAttemptsWithCorrectBackoff is the
// core coverage for #33: on persistent "no identity issued" failures, it
// must make exactly workloadDialMaxAttempts (5) probe calls and back off
// 1s, 2s, 4s, 8s between them — matching the schedule verified working in
// a real downstream consumer (bytepunx/kluster's RabbitMQ
// credential-provisioning Job) — before giving up with a wrapped error.
func TestRetryUntilIdentityIssued_ExhaustsAllAttemptsWithCorrectBackoff(t *testing.T) {
	sleeper := &fakeSleep{}
	calls := 0
	probe := func(context.Context) error {
		calls++
		return noIdentityIssuedErr()
	}

	err := retryUntilIdentityIssued(context.Background(), probe, sleeper.sleep)
	if err == nil {
		t.Fatal("expected error after exhausting all retries")
	}
	if calls != workloadDialMaxAttempts {
		t.Errorf("probe called %d times, want %d", calls, workloadDialMaxAttempts)
	}
	if got, want := len(sleeper.waited), len(workloadDialBackoff); got != want {
		t.Fatalf("slept %d times (%v), want %d (%v)", got, sleeper.waited, want, workloadDialBackoff)
	}
	for i, want := range workloadDialBackoff {
		if sleeper.waited[i] != want {
			t.Errorf("backoff[%d] = %v, want %v", i, sleeper.waited[i], want)
		}
	}
}

func TestRetryUntilIdentityIssued_UnrelatedErrorNotRetried(t *testing.T) {
	sleeper := &fakeSleep{}
	calls := 0
	wantErr := status.Error(codes.Unavailable, "connection refused")
	probe := func(context.Context) error {
		calls++
		return wantErr
	}

	err := retryUntilIdentityIssued(context.Background(), probe, sleeper.sleep)
	if err != wantErr {
		t.Errorf("got error %v, want the unwrapped unrelated error %v", err, wantErr)
	}
	if calls != 1 {
		t.Errorf("probe called %d times, want 1 (no retry on unrelated error)", calls)
	}
	if len(sleeper.waited) != 0 {
		t.Errorf("expected no backoff sleeps for an unrelated error, got %v", sleeper.waited)
	}
}

func TestRetryUntilIdentityIssued_StopsWhenSleepReportsCtxDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	calls := 0
	probe := func(context.Context) error {
		calls++
		return noIdentityIssuedErr()
	}
	sleep := func(ctx context.Context, _ time.Duration) bool {
		return ctx.Err() == nil
	}

	err := retryUntilIdentityIssued(ctx, probe, sleep)
	if err != context.Canceled {
		t.Errorf("got error %v, want context.Canceled", err)
	}
	if calls != 1 {
		t.Errorf("probe called %d times, want 1 (should stop after sleep reports ctx done)", calls)
	}
}
