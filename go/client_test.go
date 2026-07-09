package signet

import "testing"

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
	_, requireTLS, err := adminTransportCreds("localhost:8444", nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if requireTLS {
		t.Errorf("expected plaintext for loopback address without --tls")
	}
}

func TestAdminTransportCreds_NonLoopbackRequiresTLS(t *testing.T) {
	_, requireTLS, err := adminTransportCreds("signet.internal:8444", nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !requireTLS {
		t.Errorf("expected TLS to be required for a non-loopback address")
	}
}

func TestAdminTransportCreds_ForceTLSOnLoopback(t *testing.T) {
	_, requireTLS, err := adminTransportCreds("localhost:8444", nil, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !requireTLS {
		t.Errorf("expected TLS to be required when forceTLS is set")
	}
}

func TestAdminTransportCreds_InvalidCAPEM(t *testing.T) {
	_, _, err := adminTransportCreds("signet.internal:8444", []byte("not a cert"), false)
	if err == nil {
		t.Errorf("expected error for invalid CA PEM")
	}
}

func TestDialAdmin_RejectsEmptyToken(t *testing.T) {
	if _, err := DialAdmin("localhost:8444", "  ", nil, false); err == nil {
		t.Errorf("expected error for empty token")
	}
}
