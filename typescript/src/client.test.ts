// Ports every case in ../../go/client_test.go, plus interceptor-injection
// coverage the Go client doesn't need (grpc-js's insecure-credentials
// composition restriction forced a different mechanism — see client.ts's
// authInterceptor doc comment). Nothing here opens a real socket: dialAdmin
// constructs a lazy grpc-js Client, which does not connect until an RPC is
// actually invoked, and none of these tests invoke one.
import assert from "node:assert/strict";
import { test } from "node:test";
import type { InterceptorOptions, NextCall } from "@grpc/grpc-js";
import { Metadata } from "@grpc/grpc-js";
import {
  adminChannelCredentials,
  adminTransportMode,
  authInterceptor,
  dialAdmin,
  gitOpsClient,
  isLoopbackHost,
} from "./client.js";

test("isLoopbackHost matches the Go client's table", () => {
  const cases: Record<string, boolean> = {
    localhost: true,
    "127.0.0.1": true,
    "::1": true,
    "10.0.0.5": false,
    "signet.internal": false,
  };
  for (const [host, want] of Object.entries(cases)) {
    assert.equal(isLoopbackHost(host), want, `isLoopbackHost(${JSON.stringify(host)})`);
  }
});

test("adminTransportMode defaults to plaintext for a loopback address", () => {
  const { useTLS } = adminTransportMode("localhost:8444", undefined, false);
  assert.equal(useTLS, false);
});

test("adminTransportMode requires TLS for a non-loopback address", () => {
  const { useTLS } = adminTransportMode("signet.internal:8444", undefined, false);
  assert.equal(useTLS, true);
});

test("adminTransportMode requires TLS when forceTLS is set, even on loopback", () => {
  const { useTLS } = adminTransportMode("localhost:8444", undefined, true);
  assert.equal(useTLS, true);
});

test("adminTransportMode requires TLS when a CA bundle is supplied, even on loopback", () => {
  const { useTLS } = adminTransportMode("localhost:8444", "-----BEGIN CERTIFICATE-----\n...", false);
  assert.equal(useTLS, true);
});

test("adminChannelCredentials rejects an empty or whitespace-only token with a clear message", () => {
  assert.throws(
    () => adminChannelCredentials({ address: "localhost:8444", token: "  " }),
    /token must not be empty/,
  );
  assert.throws(() => adminChannelCredentials({ address: "localhost:8444", token: "" }), /token must not be empty/);
});

test("adminChannelCredentials produces a clear parse error for invalid CA PEM, not a raw OpenSSL exception", () => {
  assert.throws(
    () =>
      adminChannelCredentials({
        address: "signet.internal:8444",
        token: "tok",
        caPem: "not a cert",
      }),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.match(err.message, /signet: invalid CA PEM: no PEM certificates found in provided CA bundle/);
      return true;
    },
  );
});

test("adminChannelCredentials produces a clear parse error for a malformed-but-present PEM block", () => {
  const malformed = "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n";
  assert.throws(
    () => adminChannelCredentials({ address: "signet.internal:8444", token: "tok", caPem: malformed }),
    /signet: invalid CA PEM:/,
  );
});

test("dialAdmin constructs a client without connecting (no live network involved)", () => {
  const client = dialAdmin({ address: "localhost:8444", token: "tok" });
  client.close();
});

test("gitOpsClient constructs a client without connecting", () => {
  const client = gitOpsClient({ address: "localhost:8444", token: "tok" });
  client.close();
});

// ---------------------------------------------------------------------------
// authInterceptor
// ---------------------------------------------------------------------------

test("authInterceptor injects Authorization: Bearer <token> into every call's metadata", () => {
  const interceptor = authInterceptor("secret-token");

  let capturedMetadata: Metadata | undefined;
  const fakeCall = {
    cancelWithStatus: () => {},
    getPeer: () => "fake-peer",
    start: (metadata: Metadata) => {
      capturedMetadata = metadata;
    },
    sendMessageWithContext: () => {},
    sendMessage: () => {},
    startRead: () => {},
    halfClose: () => {},
    getAuthContext: () => null,
  };
  const nextCall: NextCall = () => fakeCall;

  const intercepting = interceptor({} as InterceptorOptions, nextCall);
  intercepting.start(new Metadata(), {
    onReceiveMetadata: () => {},
    onReceiveMessage: () => {},
    onReceiveStatus: () => {},
  });

  assert.ok(capturedMetadata, "expected the interceptor to forward metadata to nextCall.start()");
  assert.equal(capturedMetadata!.get("authorization")[0], "Bearer secret-token");
});

test("authInterceptor composes with any interceptors already present in channelOptions", () => {
  const client = dialAdmin({
    address: "localhost:8444",
    token: "tok",
    channelOptions: { interceptors: [] },
  });
  client.close();
});
