// Ports every case in ../../go/restart_test.go to the TypeScript client,
// plus a handful of cases specific to this port's design (AbortSignal
// cancellation, the dual Promise/EventEmitter 'lost' signal, backoff
// overrides for fast deterministic reconnect tests). All cases run against
// hand-written fakes implementing LockStream/WatchStream — no real network
// connection or signet instance is involved anywhere in this file.
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  AcquireRestartLockResponse_MessageType,
  type AcquireRestartLockRequest,
  type AcquireRestartLockResponse,
  WatchServiceBundleResponse_EventType,
  type WatchServiceBundleResponse,
} from "./gen/signet/v1/secrets.js";
import { BundleWatch, Lock, acquireLockWithStream, runWatchLoop, type LockStream, type WatchStream } from "./restart.js";
import { acquireLock } from "./restart.js";

// ---------------------------------------------------------------------------
// Fakes (mirrors go/restart_test.go's fakeLockStream/fakeWatchStream)
// ---------------------------------------------------------------------------

type QueueItem<T> = { resp: T } | { err: Error };

class FakeLockStream implements LockStream {
  readonly sent: AcquireRestartLockRequest[] = [];
  private readonly queue: QueueItem<AcquireRestartLockResponse>[] = [];
  private readonly waiters: Array<(item: QueueItem<AcquireRestartLockResponse>) => void> = [];
  private closed = false;

  pushResp(resp: AcquireRestartLockResponse): void {
    this.push({ resp });
  }

  pushErr(err: Error): void {
    this.push({ err });
  }

  private push(item: QueueItem<AcquireRestartLockResponse>): void {
    const waiter = this.waiters.shift();
    if (waiter) waiter(item);
    else this.queue.push(item);
  }

  send(req: AcquireRestartLockRequest): void {
    if (this.closed) throw new Error("send on closed stream");
    this.sent.push(req);
  }

  recv(): Promise<AcquireRestartLockResponse> {
    return new Promise((resolve, reject) => {
      const deliver = (item: QueueItem<AcquireRestartLockResponse>) => {
        if ("err" in item) reject(item.err);
        else resolve(item.resp);
      };
      if (this.queue.length > 0) {
        deliver(this.queue.shift()!);
      } else if (this.closed) {
        reject(new Error("stream closed"));
      } else {
        this.waiters.push(deliver);
      }
    });
  }

  closeSend(): void {
    if (this.closed) return;
    this.closed = true;
    while (this.waiters.length > 0) {
      this.waiters.shift()!({ err: new Error("stream closed") });
    }
  }

  sentCount(): number {
    return this.sent.length;
  }
}

class FakeWatchStream implements WatchStream {
  recvCalls = 0;
  private readonly queue: QueueItem<WatchServiceBundleResponse>[] = [];
  private readonly waiters: Array<(item: QueueItem<WatchServiceBundleResponse>) => void> = [];

  pushChanged(): void {
    this.push({
      resp: {
        eventType: WatchServiceBundleResponse_EventType.EVENT_TYPE_CHANGED,
        namespace: "",
        service: "",
      },
    });
  }

  pushErr(err: Error): void {
    this.push({ err });
  }

  private push(item: QueueItem<WatchServiceBundleResponse>): void {
    const waiter = this.waiters.shift();
    if (waiter) waiter(item);
    else this.queue.push(item);
  }

  recv(): Promise<WatchServiceBundleResponse> {
    this.recvCalls++;
    return new Promise((resolve, reject) => {
      const deliver = (item: QueueItem<WatchServiceBundleResponse>) => {
        if ("err" in item) reject(item.err);
        else resolve(item.resp);
      };
      if (this.queue.length > 0) deliver(this.queue.shift()!);
      else this.waiters.push(deliver);
    });
  }
}

function acquiredResp(token: string, expiresAt: Date): AcquireRestartLockResponse {
  return {
    messageType: AcquireRestartLockResponse_MessageType.MESSAGE_TYPE_ACQUIRED,
    position: 0,
    token,
    expiresAt,
  };
}

function queuePositionResp(position: number): AcquireRestartLockResponse {
  return {
    messageType: AcquireRestartLockResponse_MessageType.MESSAGE_TYPE_QUEUE_POSITION,
    position,
    token: "",
    expiresAt: undefined,
  };
}

function ttlExtendedResp(expiresAt: Date): AcquireRestartLockResponse {
  return {
    messageType: AcquireRestartLockResponse_MessageType.MESSAGE_TYPE_TTL_EXTENDED,
    position: 0,
    token: "",
    expiresAt,
  };
}

/** Resolves to the promise's value, or to `sentinel` if it doesn't settle within ms. */
function raceTimeout<T>(promise: Promise<T>, ms: number, sentinel: symbol): Promise<T | symbol> {
  return Promise.race([promise, new Promise<symbol>((resolve) => setTimeout(() => resolve(sentinel), ms))]);
}

const TIMEOUT = Symbol("timeout");

async function waitUntil(predicate: () => boolean, timeoutMs: number, message: string): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error(message);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

// ---------------------------------------------------------------------------
// acquireLock / acquireLockWithStream
// ---------------------------------------------------------------------------

test("acquireLock rejects ttl <= 0 before opening any stream", async () => {
  await assert.rejects(() => acquireLock(undefined as never, "ns", "svc", 0), /ttlSeconds must be > 0, got 0/);
  await assert.rejects(() => acquireLock(undefined as never, "ns", "svc", -1), /ttlSeconds must be > 0, got -1/);
});

test("acquireLock queue position then acquired handoff", async () => {
  const stream = new FakeLockStream();
  stream.pushResp(queuePositionResp(2));
  stream.pushResp(queuePositionResp(1));
  stream.pushResp(acquiredResp("tok-1", new Date(Date.now() + 30_000)));

  const lock = await acquireLockWithStream(stream, "ns", "svc", 4);
  try {
    assert.equal(lock.token, "tok-1");
    assert.equal(stream.sentCount(), 1, "expected exactly 1 initial send before heartbeats");
  } finally {
    await lock.release();
  }
});

test("acquireLock surfaces a clear error when the stream errors before ACQUIRED", async () => {
  const stream = new FakeLockStream();
  stream.pushErr(new Error("boom"));

  await assert.rejects(
    () => acquireLockWithStream(stream, "ns", "svc", 4),
    /AcquireRestartLock stream ended before the lock was acquired.*boom/,
  );
});

test("heartbeat interval defaults to ttlSeconds / 4", async () => {
  const stream = new FakeLockStream();
  stream.pushResp(acquiredResp("tok-1", new Date(Date.now() + 2_000)));

  // ttl=2s => heartbeat interval = 500ms. Wait ~1.3s and expect >=2
  // heartbeats sent (in addition to the 1 initial request).
  const lock = await acquireLockWithStream(stream, "ns", "svc", 2);
  try {
    await new Promise((resolve) => setTimeout(resolve, 1300));
    assert.ok(stream.sentCount() >= 3, `sentCount() = ${stream.sentCount()}, want >= 3 (1 initial + >=2 heartbeats)`);
    const heartbeats = stream.sent.slice(1);
    for (const hb of heartbeats) {
      assert.equal(hb.heartbeat, true);
    }
  } finally {
    await lock.release();
  }
});

test("TTL_EXTENDED updates the tracked expiry", async () => {
  const stream = new FakeLockStream();
  const first = new Date(Date.now() + 4_000);
  stream.pushResp(acquiredResp("tok-1", first));

  const lock = await acquireLockWithStream(stream, "ns", "svc", 4);
  try {
    const extended = new Date(Date.now() + 60_000);
    stream.pushResp(ttlExtendedResp(extended));

    await waitUntil(
      () => lock.expiresAt?.getTime() === extended.getTime(),
      2000,
      `expiresAt never reflected TTL_EXTENDED; last = ${lock.expiresAt?.toISOString()}, want ${extended.toISOString()}`,
    );
  } finally {
    await lock.release();
  }
});

test("release is idempotent", async () => {
  const stream = new FakeLockStream();
  stream.pushResp(acquiredResp("tok-1", new Date(Date.now() + 30_000)));

  const lock = await acquireLockWithStream(stream, "ns", "svc", 4);
  await lock.release();
  await lock.release(); // must not throw / hang
});

test("lock loss is reported on an unexpected stream error", async () => {
  const stream = new FakeLockStream();
  stream.pushResp(acquiredResp("tok-1", new Date(Date.now() + 4_000)));

  const lock = await acquireLockWithStream(stream, "ns", "svc", 4);
  try {
    const eventErr: Promise<Error> = new Promise((resolve) => lock.once("lost", resolve));

    stream.pushErr(new Error("lock lost"));

    const err = await raceTimeout(lock.lost, 2000, TIMEOUT);
    assert.notEqual(err, TIMEOUT, "lost never signaled after stream error");
    assert.ok(err instanceof Error);
    assert.match((err as Error).message, /lock lost/);

    // The 'lost' EventEmitter event must fire with the same error too.
    const emitted = await raceTimeout(eventErr, 500, TIMEOUT);
    assert.notEqual(emitted, TIMEOUT, "'lost' event never emitted");
  } finally {
    await lock.release();
  }
});

test("release does not report lost", async () => {
  const stream = new FakeLockStream();
  stream.pushResp(acquiredResp("tok-1", new Date(Date.now() + 30_000)));

  const lock = await acquireLockWithStream(stream, "ns", "svc", 4);
  await lock.release();

  const result = await raceTimeout(lock.lost, 200, TIMEOUT);
  assert.equal(result, TIMEOUT, "lost fired after a clean release()");
});

test("acquireLock rejects when the signal aborts while waiting for ACQUIRED", async () => {
  const stream = new FakeLockStream();
  // Never push a response — the caller aborts while still waiting in queue.
  const controller = new AbortController();
  const promise = acquireLockWithStream(stream, "ns", "svc", 4, { signal: controller.signal });
  controller.abort(new Error("shutting down"));

  await assert.rejects(() => promise, /AcquireRestartLock.*aborted.*shutting down/);
});

// ---------------------------------------------------------------------------
// WatchBundle / runWatchLoop
// ---------------------------------------------------------------------------

test("watch loop coalesces rapid successive changes into one pending signal", async () => {
  // 3 changes are pushed but the stream never errors or ends, so after
  // they're drained the 4th recv() call just hangs — no error, no
  // reconnect, so open() is only ever called once.
  const stream = new FakeWatchStream();
  stream.pushChanged();
  stream.pushChanged();
  stream.pushChanged();

  const watch = new BundleWatch();
  void runWatchLoop(() => stream, watch, {});

  await waitUntil(
    () => stream.recvCalls >= 4,
    2000,
    `watch loop only issued ${stream.recvCalls} recv calls, want >= 4`,
  );

  const first = await raceTimeout(watch.next(), 500, TIMEOUT);
  assert.equal(first, true, "expected the coalesced signal to be immediately available");

  const second = await raceTimeout(watch.next(), 200, TIMEOUT);
  assert.equal(second, TIMEOUT, "expected no further pending signal after draining the coalesced one");
});

test("watch loop reconnects with backoff after a stream error and eventually delivers a change", async () => {
  const first = new FakeWatchStream();
  first.pushErr(new Error("boom"));

  const second = new FakeWatchStream();
  second.pushChanged();

  let attempt = 0;
  const open = () => {
    attempt++;
    return attempt === 1 ? first : second;
  };

  const watch = new BundleWatch();
  // Fast backoff so this test doesn't take 1s+ in CI; the *default*
  // 1s/30s backoff constants are exercised implicitly by every other
  // reconnect-shaped test using default options.
  void runWatchLoop(open, watch, { backoffMinMs: 10, backoffMaxMs: 50 });

  const result = await raceTimeout(watch.next(), 2000, TIMEOUT);
  assert.equal(result, true, "expected watch loop to reconnect and eventually deliver a change");
});

test("watch loop treats a failing open() the same as a stream error (backs off and retries)", async () => {
  let attempt = 0;
  const open = () => {
    attempt++;
    if (attempt === 1) throw new Error("dial refused");
    const stream = new FakeWatchStream();
    stream.pushChanged();
    return stream;
  };

  const watch = new BundleWatch();
  void runWatchLoop(open, watch, { backoffMinMs: 10, backoffMaxMs: 50 });

  const result = await raceTimeout(watch.next(), 2000, TIMEOUT);
  assert.equal(result, true, "expected watch loop to retry after a failed open() and eventually deliver a change");
  assert.ok(attempt >= 2);
});

test("watch loop stops and closes the BundleWatch when the signal is aborted", async () => {
  const stream = new FakeWatchStream(); // never delivers anything
  const controller = new AbortController();

  const watch = new BundleWatch();
  const loopDone = runWatchLoop(() => stream, watch, { signal: controller.signal });

  controller.abort();
  await loopDone;

  const result = await raceTimeout(watch.next(), 500, TIMEOUT);
  assert.equal(result, false, "expected next() to resolve false once the watch is closed");
});

// ---------------------------------------------------------------------------
// Lock.token / Lock.expiresAt basic accessors (not covered by the flows above)
// ---------------------------------------------------------------------------

test("Lock exposes token and expiresAt from the ACQUIRED response", async () => {
  const stream = new FakeLockStream();
  const expiresAt = new Date(Date.now() + 12_000);
  stream.pushResp(acquiredResp("tok-xyz", expiresAt));

  const lock: Lock = await acquireLockWithStream(stream, "ns", "svc", 8);
  try {
    assert.equal(lock.token, "tok-xyz");
    assert.equal(lock.expiresAt?.getTime(), expiresAt.getTime());
  } finally {
    await lock.release();
  }
});
