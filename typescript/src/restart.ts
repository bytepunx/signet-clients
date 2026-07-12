// Coordinated-restart support: watchBundle/acquireLock/waitForRestart let a
// service pull its own configuration directly and in-memory, and safely
// coordinate a fleet-wide serialized restart when it changes. This mirrors
// the Go client's restart.go — see ../README.md's "Coordinated restarts"
// section for the full design rationale (in short: no child-process
// spawning, no writing secrets to the environment, no bundle refetch after
// the lock is acquired — the *next* process instance fetches fresh config
// during its own normal startup).
import { EventEmitter } from "node:events";
import type { ClientDuplexStream, ClientReadableStream } from "@grpc/grpc-js";
import {
  AcquireRestartLockResponse_MessageType,
  type AcquireRestartLockRequest,
  type AcquireRestartLockResponse,
  type SecretsServiceClient,
  WatchServiceBundleResponse_EventType,
  type WatchServiceBundleResponse,
} from "./gen/signet/v1/secrets.js";
import { AsyncMailbox } from "./async-mailbox.js";
import { AbortRaceError, abortedError, asError, errMessage, raceAbort } from "./errors.js";

const DEFAULT_BACKOFF_MIN_MS = 1000;
const DEFAULT_BACKOFF_MAX_MS = 30000;

// ---------------------------------------------------------------------------
// Stream abstractions
// ---------------------------------------------------------------------------

/**
 * LockStream is the subset of a signet AcquireRestartLock duplex stream that
 * acquireLockWithStream depends on, so tests can substitute a hand-written
 * fake instead of a real gRPC stream (mirrors the Go client's lockStream
 * interface).
 */
export interface LockStream {
  send(req: AcquireRestartLockRequest): void;
  recv(): Promise<AcquireRestartLockResponse>;
  closeSend(): void;
}

/**
 * WatchStream is the subset of a signet WatchServiceBundle stream that
 * runWatchLoop depends on (mirrors the Go client's watchStream interface).
 */
export interface WatchStream {
  recv(): Promise<WatchServiceBundleResponse>;
}

/** Wraps a real grpc-js duplex stream as a LockStream. */
export function lockStreamFromGrpc(
  stream: ClientDuplexStream<AcquireRestartLockRequest, AcquireRestartLockResponse>,
): LockStream {
  const mailbox = new AsyncMailbox<AcquireRestartLockResponse>();
  stream.on("data", (msg: AcquireRestartLockResponse) => mailbox.pushValue(msg));
  stream.on("error", (err: Error) => mailbox.pushTerminal({ kind: "error", error: asError(err) }));
  stream.on("end", () => mailbox.pushTerminal({ kind: "done" }));

  let sendClosed = false;
  return {
    send(req: AcquireRestartLockRequest) {
      if (sendClosed) {
        throw new Error("signet: cannot send on AcquireRestartLock stream after Release/closeSend");
      }
      stream.write(req);
    },
    async recv(): Promise<AcquireRestartLockResponse> {
      const item = await mailbox.next();
      if (item.kind === "value") return item.value;
      if (item.kind === "error") throw item.error;
      throw new Error("signet: AcquireRestartLock stream closed by server");
    },
    closeSend() {
      if (sendClosed) return;
      sendClosed = true;
      stream.end();
    },
  };
}

/** Wraps a real grpc-js readable stream as a WatchStream. */
export function watchStreamFromGrpc(stream: ClientReadableStream<WatchServiceBundleResponse>): WatchStream {
  const mailbox = new AsyncMailbox<WatchServiceBundleResponse>();
  stream.on("data", (msg: WatchServiceBundleResponse) => mailbox.pushValue(msg));
  stream.on("error", (err: Error) => mailbox.pushTerminal({ kind: "error", error: asError(err) }));
  stream.on("end", () => mailbox.pushTerminal({ kind: "done" }));

  return {
    async recv(): Promise<WatchServiceBundleResponse> {
      const item = await mailbox.next();
      if (item.kind === "value") return item.value;
      if (item.kind === "error") throw item.error;
      throw new Error("signet: WatchServiceBundle stream closed by server");
    },
  };
}

// ---------------------------------------------------------------------------
// WatchBundle
// ---------------------------------------------------------------------------

export interface WatchBundleOptions {
  signal?: AbortSignal;
  /** Overrides the initial/minimum reconnect backoff (default 1000ms). */
  backoffMinMs?: number;
  /** Overrides the reconnect backoff cap (default 30000ms). */
  backoffMaxMs?: number;
}

/**
 * BundleWatch delivers "at least one change happened" signals, coalescing
 * rapid successive changes: a consumer that hasn't drained the previous
 * signal never sees a backlog. This mirrors the Go client's buffered
 * (capacity 1) `<-chan struct{}`.
 */
export class BundleWatch {
  private pending = false;
  private closed = false;
  private readonly waiters: Array<(changed: boolean) => void> = [];

  /** @internal */
  _signalChange(): void {
    if (this.closed || this.pending) return;
    const waiter = this.waiters.shift();
    if (waiter) {
      waiter(true);
    } else {
      this.pending = true;
    }
  }

  /** @internal */
  _close(): void {
    if (this.closed) return;
    this.closed = true;
    while (this.waiters.length > 0) {
      this.waiters.shift()!(false);
    }
  }

  /**
   * Resolves true once a change has occurred since the last call to next(),
   * or false once watching has stopped for good (the signal passed to
   * watchBundle was aborted).
   */
  next(): Promise<boolean> {
    if (this.pending) {
      this.pending = false;
      return Promise.resolve(true);
    }
    if (this.closed) {
      return Promise.resolve(false);
    }
    return new Promise((resolve) => this.waiters.push(resolve));
  }

  /** Iterates once per change signal, ending when watching stops. */
  async *[Symbol.asyncIterator](): AsyncGenerator<void, void, void> {
    while (await this.next()) {
      yield;
    }
  }
}

/**
 * runWatchLoop is the core, transport-agnostic reconnect/backoff/coalesce
 * state machine, exported so tests can drive it against a hand-written
 * WatchStream fake instead of a real connection (mirrors the Go client's
 * watchLoop). open() may fail (reject) to simulate a dial error without ever
 * producing a stream, which — like a stream recv error — triggers backoff
 * and a retry.
 */
export async function runWatchLoop(
  open: () => WatchStream | Promise<WatchStream>,
  watch: BundleWatch,
  opts: WatchBundleOptions = {},
): Promise<void> {
  const backoffMin = opts.backoffMinMs ?? DEFAULT_BACKOFF_MIN_MS;
  const backoffMax = opts.backoffMaxMs ?? DEFAULT_BACKOFF_MAX_MS;
  const signal = opts.signal;
  let backoff = backoffMin;

  try {
    for (;;) {
      if (signal?.aborted) return;

      let stream: WatchStream;
      try {
        // Wrapped in an async IIFE so a synchronous throw from open() (e.g.
        // simulating a dial error in tests) becomes a rejection uniformly,
        // alongside a genuinely async open() failing later.
        stream = await raceAbort(
          (async () => open())(),
          signal,
        );
      } catch (err) {
        if (err instanceof AbortRaceError) return;
        if (!(await sleepOrAborted(backoff, signal))) return;
        backoff = nextBackoff(backoff, backoffMax);
        continue;
      }

      for (;;) {
        let resp: WatchServiceBundleResponse;
        try {
          // Raced against the signal directly (not just checked between
          // iterations) because an abstract WatchStream's recv() may never
          // settle on its own — only the real gRPC adapter ties
          // cancellation into the underlying stream via .cancel().
          resp = await raceAbort(stream.recv(), signal);
        } catch (err) {
          if (err instanceof AbortRaceError) return;
          break;
        }
        backoff = backoffMin;
        if (resp.eventType === WatchServiceBundleResponse_EventType.EVENT_TYPE_CHANGED) {
          watch._signalChange();
        }
      }

      if (signal?.aborted) return;
      if (!(await sleepOrAborted(backoff, signal))) return;
      backoff = nextBackoff(backoff, backoffMax);
    }
  } finally {
    watch._close();
  }
}

function nextBackoff(current: number, max: number): number {
  return Math.min(current * 2, max);
}

/** Resolves true after ms elapse, or false immediately if signal aborts first (or is already aborted). */
function sleepOrAborted(ms: number, signal?: AbortSignal): Promise<boolean> {
  if (signal?.aborted) return Promise.resolve(false);
  return new Promise((resolve) => {
    const onAbort = () => {
      clearTimeout(timer);
      resolve(false);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve(true);
    }, ms);
    timer.unref?.();
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * watchBundle watches for signet bundle-change notifications for
 * namespace/service, reconnecting with exponential backoff (1s, doubling,
 * capped at 30s by default, reset to 1s on any successful receive) if the
 * stream breaks.
 */
export function watchBundle(
  client: SecretsServiceClient,
  namespace: string,
  service: string,
  opts: WatchBundleOptions = {},
): BundleWatch {
  const watch = new BundleWatch();

  const open = (): WatchStream => {
    const grpcStream = client.watchServiceBundle({ namespace, service });
    const signal = opts.signal;
    if (signal) {
      if (signal.aborted) {
        grpcStream.cancel();
      } else {
        signal.addEventListener("abort", () => grpcStream.cancel(), { once: true });
      }
    }
    return watchStreamFromGrpc(grpcStream);
  };

  // Errors from runWatchLoop itself (as opposed to from open()/recv(), which
  // it already handles internally) are not expected in normal operation;
  // BundleWatch communicates state via next()/_close(), not exceptions, so
  // there is nothing further to do with a rejection here besides not
  // crashing the process with an unhandled rejection.
  void runWatchLoop(open, watch, opts);

  return watch;
}

// ---------------------------------------------------------------------------
// AcquireLock / Lock
// ---------------------------------------------------------------------------

export interface AcquireLockOptions {
  signal?: AbortSignal;
  /** Overrides the derived ttlSeconds/4 heartbeat interval, mainly for tests. */
  heartbeatIntervalMs?: number;
}

/**
 * Lock represents a held signet restart lock. Call release() once your own
 * graceful shutdown (draining in-flight work, closing resources) is
 * complete, immediately before exiting.
 *
 * Loss of the lock (a stream error, or the server closing the stream) before
 * an intentional release is reported both as an EventEmitter 'lost' event
 * and via the `lost` promise — `lost` resolves at most once, only on loss,
 * and never settles at all after a clean release(), so racing it (e.g. with
 * Promise.race or `await`) safely distinguishes loss from an intentional
 * release with no risk of missing the event if a listener is attached late.
 */
export class Lock extends EventEmitter {
  private readonly stream: LockStream;
  private _token = "";
  private _expiresAt: Date | undefined;
  private released = false;
  private lostReported = false;
  private heartbeatTimer: ReturnType<typeof setInterval> | undefined;
  private readonly recvDone: Promise<void>;
  private resolveRecvDone!: () => void;
  private readonly lostPromise: Promise<Error>;
  private resolveLost!: (err: Error) => void;

  constructor(stream: LockStream) {
    super();
    this.stream = stream;
    this.recvDone = new Promise((resolve) => {
      this.resolveRecvDone = resolve;
    });
    this.lostPromise = new Promise((resolve) => {
      this.resolveLost = resolve;
    });
  }

  /** Identifies this lock acquisition, for audit/logging purposes. */
  get token(): string {
    return this._token;
  }

  /** The lock's current expiry, updated as heartbeats are acknowledged (TTL_EXTENDED). */
  get expiresAt(): Date | undefined {
    return this._expiresAt;
  }

  /**
   * Resolves with an error if the lock is lost unexpectedly (stream error,
   * or the server closing the stream) before release() is called. Never
   * settles if release() completes first. Treat a resolution as "another
   * replica may now acquire and restart concurrently" — there is nothing to
   * undo, only to log.
   */
  get lost(): Promise<Error> {
    return this.lostPromise;
  }

  /** Closes the lock stream, releasing the lock for the next waiting replica. Idempotent. */
  async release(): Promise<void> {
    if (this.released) return;
    this.released = true;
    this.stopHeartbeat();
    try {
      this.stream.closeSend();
    } finally {
      await this.recvDone; // wait for the recv loop to observe the close and exit
    }
  }

  /** @internal */
  _setAcquired(token: string, expiresAt: Date | undefined): void {
    this._token = token;
    this._expiresAt = expiresAt;
  }

  /** @internal */
  _updateExpiry(expiresAt: Date | undefined): void {
    if (expiresAt) this._expiresAt = expiresAt;
  }

  /** @internal */
  _reportLost(err: Error): void {
    if (this.released || this.lostReported) return;
    this.lostReported = true;
    this.resolveLost(err);
    this.emit("lost", err);
  }

  /** @internal */
  _finishRecvLoop(): void {
    this.resolveRecvDone();
  }

  /** @internal */
  _startHeartbeat(intervalMs: number): void {
    const interval = Math.max(1, intervalMs);
    this.heartbeatTimer = setInterval(() => {
      try {
        this.stream.send({ namespace: "", service: "", ttlSeconds: 0, heartbeat: true });
      } catch (err) {
        this.stopHeartbeat();
        this._reportLost(asError(err));
      }
    }, interval);
    this.heartbeatTimer.unref?.();
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = undefined;
    }
  }
}

/**
 * acquireLockWithStream drives the AcquireRestartLock state machine over an
 * already-open LockStream: send the initial request, drain QUEUE_POSITION
 * messages until ACQUIRED, then keep reading TTL_EXTENDED acks (updating the
 * tracked expiry) and heartbeating at ttlSeconds/4 until release() is
 * called or the lock is lost. Exported (alongside the LockStream interface)
 * so tests can drive it with a hand-written fake instead of a real stream.
 */
export async function acquireLockWithStream(
  stream: LockStream,
  namespace: string,
  service: string,
  ttlSeconds: number,
  opts: AcquireLockOptions = {},
): Promise<Lock> {
  const ttlSecs = Math.max(1, Math.trunc(ttlSeconds));

  try {
    stream.send({ namespace, service, ttlSeconds: ttlSecs, heartbeat: false });
  } catch (err) {
    throw new Error(`signet: send initial AcquireRestartLock request: ${errMessage(err)}`);
  }

  const lock = new Lock(stream);
  let gotAcquired = false;

  const acquired = new Promise<void>((resolve, reject) => {
    (async () => {
      for (;;) {
        let resp: AcquireRestartLockResponse;
        try {
          resp = await stream.recv();
        } catch (err) {
          const wrapped = asError(err);
          if (!gotAcquired) {
            reject(
              new Error(`signet: AcquireRestartLock stream ended before the lock was acquired: ${wrapped.message}`),
            );
          } else {
            lock._reportLost(wrapped);
          }
          lock._finishRecvLoop();
          return;
        }

        switch (resp.messageType) {
          case AcquireRestartLockResponse_MessageType.MESSAGE_TYPE_ACQUIRED:
            lock._setAcquired(resp.token, resp.expiresAt);
            if (!gotAcquired) {
              gotAcquired = true;
              const intervalMs = opts.heartbeatIntervalMs ?? Math.max(1, Math.floor((ttlSecs * 1000) / 4));
              lock._startHeartbeat(intervalMs);
              resolve();
            }
            break;
          case AcquireRestartLockResponse_MessageType.MESSAGE_TYPE_TTL_EXTENDED:
            lock._updateExpiry(resp.expiresAt);
            break;
          case AcquireRestartLockResponse_MessageType.MESSAGE_TYPE_QUEUE_POSITION:
          default:
            // No state to update; callers who want position visibility can
            // wrap acquireLock and race their own recv against the exposed
            // primitives if that becomes a real need (same tradeoff the Go
            // client documents).
            break;
        }
      }
    })();
  });

  const signal = opts.signal;
  if (!signal) {
    await acquired;
    return lock;
  }

  try {
    await raceAbort(acquired, signal);
  } catch (err) {
    // Aborted (or otherwise failed) before acquisition: best-effort close so
    // the background recv loop above doesn't run forever waiting on a
    // stream nobody will read from again.
    try {
      stream.closeSend();
    } catch {
      // ignore — closeSend is already documented as best-effort here
    }
    if (err instanceof AbortRaceError) {
      throw abortedError(signal, "AcquireRestartLock");
    }
    throw err;
  }

  return lock;
}

/**
 * acquireLock blocks until this replica acquires signet's restart lock for
 * namespace/service, queueing behind any current holder. ttlSeconds must be
 * > 0 and must cover the full time between acquiring the lock and calling
 * lock.release() — signet has no server-side default. Heartbeats are sent
 * automatically at ttlSeconds/4 (signet's documented convention: 4
 * consecutive missed heartbeats exhaust the TTL) until release() is called,
 * the signal is aborted, or the lock is lost (see Lock.lost).
 */
export async function acquireLock(
  client: SecretsServiceClient,
  namespace: string,
  service: string,
  ttlSeconds: number,
  opts: AcquireLockOptions = {},
): Promise<Lock> {
  if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
    throw new Error(`signet: ttlSeconds must be > 0, got ${ttlSeconds}`);
  }

  let grpcStream: ClientDuplexStream<AcquireRestartLockRequest, AcquireRestartLockResponse>;
  try {
    grpcStream = client.acquireRestartLock();
  } catch (err) {
    throw new Error(`signet: open AcquireRestartLock stream: ${errMessage(err)}`);
  }

  return acquireLockWithStream(lockStreamFromGrpc(grpcStream), namespace, service, ttlSeconds, opts);
}

// ---------------------------------------------------------------------------
// WaitForRestart
// ---------------------------------------------------------------------------

/**
 * waitForRestart is a convenience combining watchBundle and acquireLock: it
 * waits for the next bundle change (debounced by debounceMs — 0 means act on
 * the first event immediately), then acquires the restart lock, returning
 * once held. It does not fetch the updated bundle: since this call doesn't
 * spawn a replacement process, the next process instance fetches it fresh
 * during its own normal startup.
 */
export async function waitForRestart(
  client: SecretsServiceClient,
  namespace: string,
  service: string,
  ttlSeconds: number,
  debounceMs: number,
  opts: { signal?: AbortSignal } = {},
): Promise<Lock> {
  const watch = watchBundle(client, namespace, service, { signal: opts.signal });

  const first = await watch.next();
  if (!first) {
    throw abortedError(opts.signal, "waitForRestart");
  }

  if (debounceMs > 0) {
    await debounceUntilQuiet(watch, debounceMs, opts.signal);
  }

  return acquireLock(client, namespace, service, ttlSeconds, { signal: opts.signal });
}

async function debounceUntilQuiet(watch: BundleWatch, debounceMs: number, signal?: AbortSignal): Promise<void> {
  let pendingChange = watch.next();
  for (;;) {
    const timerCompleted = sleepOrAborted(debounceMs, signal);
    const winner = await Promise.race([
      pendingChange.then((ok) => ({ kind: "change" as const, ok })),
      timerCompleted.then((completed) => ({ kind: "timer" as const, completed })),
    ]);

    if (winner.kind === "timer") {
      if (!winner.completed) throw abortedError(signal, "waitForRestart");
      return;
    }

    if (!winner.ok) throw abortedError(signal, "waitForRestart");
    pendingChange = watch.next();
  }
}
