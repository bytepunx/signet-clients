//! Coordinated-restart support: watching for signet bundle changes and
//! serializing a fleet-wide restart via signet's distributed restart lock.
//!
//! Mirrors `go/restart.go`. See `docs/restart-lock.md` in the main signet
//! repo for the authoritative protocol description, and this crate's
//! `README.md` for the design rationale (why a lock instead of client-side
//! jitter, why heartbeat at `ttl/4`, why this library never refetches the
//! bundle or exits the process itself).
//!
//! ## Design differences from the Go client
//!
//! Go's `AcquireLock`/`WatchBundle` each spawn a goroutine that owns a
//! `context.Context`-cancellable blocking `Recv()` call for the stream's
//! entire lifetime, because Go's synchronous `Recv()` can't itself be
//! selected against a cancellation signal. Rust's `async` streams don't have
//! that limitation — `stream.recv()` is itself just another future, so it
//! composes directly with `tokio::select!` alongside a heartbeat timer and a
//! release signal in a *single* task, and (for [`acquire_lock`]) the
//! "waiting to be acquired" phase runs directly in the caller's own future
//! rather than a detached task, so cooperative cancellation (e.g.
//! `tokio::time::timeout(..., acquire_lock(...))`) works for free before
//! acquisition succeeds, without needing to thread a cancellation token
//! through by hand.
//!
//! Once a lock *is* acquired, a single task is spawned to own the stream for
//! the rest of its hold duration (heartbeating and reading `TTL_EXTENDED`
//! acks / detecting loss), exactly mirroring the Go client's requirement
//! that "a single goroutine/task must continuously read the stream for its
//! entire hold duration."

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;

use crate::signet::v1::acquire_restart_lock_response::MessageType;
use crate::signet::v1::secrets_service_client::SecretsServiceClient;
use crate::signet::v1::watch_service_bundle_response::EventType;
use crate::signet::v1::{
    AcquireRestartLockRequest, AcquireRestartLockResponse, WatchServiceBundleRequest,
    WatchServiceBundleResponse,
};

const WATCH_BACKOFF_MIN: Duration = Duration::from_secs(1);
const WATCH_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Errors returned by the restart-coordination primitives in this module.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RestartError {
    /// [`acquire_lock`] (or [`wait_for_restart`]) was called with a
    /// non-positive TTL. Returned before any stream is opened.
    #[error("signet: ttl must be > 0, got {0:?}")]
    InvalidTtl(Duration),

    /// Opening the `AcquireRestartLock` bidirectional stream failed.
    #[error("signet: open AcquireRestartLock stream: {0}")]
    OpenStream(String),

    /// Sending a message on the `AcquireRestartLock` stream failed.
    #[error("signet: send AcquireRestartLockRequest: {0}")]
    Send(String),

    /// Receiving a message from the `AcquireRestartLock` stream failed.
    #[error("signet: receive AcquireRestartLockResponse: {0}")]
    Recv(String),

    /// The stream closed (or ended cleanly) before an `ACQUIRED` message was
    /// ever received.
    #[error("signet: AcquireRestartLock stream closed before the lock was acquired")]
    ClosedBeforeAcquired,

    /// The lock was lost unexpectedly (stream error, or the server closing
    /// the stream) while held — i.e. *not* as a result of calling
    /// [`Lock::release`]. See [`Lock::lost`].
    #[error("signet: restart lock lost: {0}")]
    LockLost(String),

    /// Opening the `WatchServiceBundle` stream failed.
    #[error("signet: open WatchServiceBundle stream: {0}")]
    WatchOpen(String),

    /// [`wait_for_restart`]'s change-watch stopped (the supplied
    /// [`CancellationToken`] fired) before a change was observed.
    #[error("signet: watch_bundle stopped before a restart could be coordinated")]
    WatchStopped,

    /// The supplied [`CancellationToken`] fired.
    #[error("signet: cancelled")]
    Cancelled,
}

// ---------------------------------------------------------------------
// AcquireRestartLock / Lock
// ---------------------------------------------------------------------

/// The subset of stream operations [`acquire_lock`] depends on, so tests can
/// substitute a hand-written fake instead of a real gRPC stream. Mirrors Go's
/// `lockStream` interface (`Send`/`Recv`/`CloseSend`).
trait LockStream: Send {
    fn send(
        &mut self,
        req: AcquireRestartLockRequest,
    ) -> impl Future<Output = Result<(), RestartError>> + Send;

    fn recv(
        &mut self,
    ) -> impl Future<Output = Result<Option<AcquireRestartLockResponse>, RestartError>> + Send;

    fn close_send(&mut self) -> impl Future<Output = Result<(), RestartError>> + Send;
}

/// The live gRPC-backed implementation of [`LockStream`]. Tonic splits a
/// bidi-streaming call into an outbound `Sender` (fed into the RPC as the
/// request stream) and an inbound `Streaming<Response>`; `close_send` is
/// implemented by dropping the sender, which ends the outbound stream (there
/// is no separate `CloseSend` call in tonic's client API).
struct RealLockStream {
    tx: Option<mpsc::Sender<AcquireRestartLockRequest>>,
    inbound: tonic::codec::Streaming<AcquireRestartLockResponse>,
}

impl LockStream for RealLockStream {
    async fn send(&mut self, req: AcquireRestartLockRequest) -> Result<(), RestartError> {
        match &self.tx {
            Some(tx) => tx
                .send(req)
                .await
                .map_err(|_| RestartError::Send("stream already closed".to_string())),
            None => Err(RestartError::Send("stream already closed".to_string())),
        }
    }

    async fn recv(&mut self) -> Result<Option<AcquireRestartLockResponse>, RestartError> {
        self.inbound
            .message()
            .await
            .map_err(|status| RestartError::Recv(status.to_string()))
    }

    async fn close_send(&mut self) -> Result<(), RestartError> {
        self.tx = None;
        Ok(())
    }
}

struct LockState {
    token: String,
    expires_at: Option<prost_types::Timestamp>,
}

/// A held signet restart lock.
///
/// Call [`Lock::release`] once your own graceful shutdown (draining
/// in-flight work, closing resources) is complete, immediately before
/// exiting.
///
/// ## Release semantics: idempotent `&self`, not consuming `self`
///
/// Unlike a Rust API that takes `self` (making a double-release a compile
/// error), `release` takes `&self` and is runtime-idempotent — calling it
/// twice is safe, and the second call is a no-op. This mirrors the Go
/// client's design deliberately: a `Lock` represents a live network
/// resource (an open bidirectional stream plus a background task) whose
/// lifecycle is coordinated asynchronously, not a value that's naturally
/// consumed at a single call site. Realistic shutdown paths — a signal
/// handler racing a normal shutdown sequence, or a `Drop` guard alongside an
/// explicit call — benefit more from "safe to call from two places" than
/// from a compile-time single-use guarantee, which would force an
/// `Option<Lock>`/`.take()` dance at every call site just to satisfy the
/// borrow checker.
///
/// Dropping a `Lock` without calling `release` does **not** release the
/// lock or stop the background heartbeat task — exactly like dropping the
/// Go client's `*Lock` without calling `Release` doesn't stop its goroutine.
/// The task keeps heartbeating until the process exits, `release()` is
/// called, or the stream itself errors out.
pub struct Lock {
    state: Arc<StdMutex<LockState>>,
    lost_rx: watch::Receiver<Option<Arc<RestartError>>>,
    release_tx: StdMutex<Option<oneshot::Sender<()>>>,
    done_rx: StdMutex<Option<oneshot::Receiver<()>>>,
    released: Arc<AtomicBool>,
}

impl std::fmt::Debug for Lock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lock")
            .field("token", &self.token())
            .field("expires_at", &self.expires_at())
            .field("released", &self.released.load(Ordering::SeqCst))
            .finish()
    }
}

impl Lock {
    /// Identifies this lock acquisition, for audit/logging purposes.
    pub fn token(&self) -> String {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).token.clone()
    }

    /// Returns the lock's current expiry, updated as heartbeats are
    /// acknowledged (`TTL_EXTENDED`).
    pub fn expires_at(&self) -> Option<prost_types::Timestamp> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).expires_at
    }

    /// Returns a receiver that reports, at most once, an error if the lock
    /// is lost unexpectedly (stream error, or the server closing the
    /// stream) before [`Lock::release`] is called.
    ///
    /// Call `.changed().await` then `.borrow()` to wait for the value to
    /// become `Some`. The caller should treat a loss as "another replica
    /// may now acquire and restart concurrently" — there is nothing to
    /// undo, only to log. An intentional [`Lock::release`] never populates
    /// this.
    ///
    /// Note that once the lock's background task exits (after a loss *or*
    /// after `release()`), its `watch::Sender` half is dropped, so a
    /// `.changed()` call made afterwards resolves immediately with `Err`
    /// rather than hanging forever — a reasonable "no further updates are
    /// possible" signal, but callers that care about *which* case occurred
    /// should check `.borrow()`'s value, not just whether `.changed()`
    /// returned.
    pub fn lost(&self) -> watch::Receiver<Option<Arc<RestartError>>> {
        self.lost_rx.clone()
    }

    /// Closes the lock stream, releasing the lock for the next waiting
    /// replica. Safe to call more than once — see the type-level docs for
    /// why this is idempotent rather than consuming.
    pub async fn release(&self) -> Result<(), RestartError> {
        if self.released.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        if let Some(tx) = self.release_tx.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = tx.send(());
        }

        let done_rx = self.done_rx.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(done_rx) = done_rx {
            // Wait for the background task to observe the close and exit,
            // mirroring Go's `<-l.recvDoneCh`.
            let _ = done_rx.await;
        }

        Ok(())
    }
}

/// Rejects `ttl <= 0` (Rust's unsigned `Duration` can't be negative, so this
/// is `ttl.is_zero()`) before any stream is ever opened, and converts to the
/// whole-second `i32` the wire protocol requires — truncating like Go's
/// `int32(ttl / time.Second)`, with the same "round sub-second TTLs up to at
/// least 1 second" floor.
fn validate_ttl(ttl: Duration) -> Result<i32, RestartError> {
    if ttl.is_zero() {
        return Err(RestartError::InvalidTtl(ttl));
    }
    let secs = ttl.as_secs();
    let secs = if secs == 0 { 1 } else { secs };
    i32::try_from(secs).map_err(|_| RestartError::InvalidTtl(ttl))
}

/// Blocks until this replica acquires signet's restart lock for
/// `namespace`/`service`, queueing behind any current holder.
///
/// `ttl` must be `> 0` and must cover the full time between acquiring the
/// lock and calling [`Lock::release`] — signet has no server-side default.
/// Heartbeats are sent automatically at `ttl/4` (signet's documented
/// convention: 4 consecutive missed heartbeats exhaust the TTL) until
/// `release` is called or the lock is lost (see [`Lock::lost`]).
pub async fn acquire_lock(
    mut client: SecretsServiceClient<Channel>,
    namespace: impl Into<String>,
    service: impl Into<String>,
    ttl: Duration,
) -> Result<Lock, RestartError> {
    let ttl_secs = validate_ttl(ttl)?;
    let namespace = namespace.into();
    let service = service.into();

    let (tx, rx) = mpsc::channel(4);
    let response = client
        .acquire_restart_lock(ReceiverStream::new(rx))
        .await
        .map_err(|status| RestartError::OpenStream(status.to_string()))?;

    let stream = RealLockStream {
        tx: Some(tx),
        inbound: response.into_inner(),
    };

    acquire_lock_with(stream, namespace, service, ttl_secs).await
}

/// The generic core of [`acquire_lock`], tested directly against
/// hand-written [`LockStream`] fakes.
async fn acquire_lock_with<S: LockStream + Send + 'static>(
    mut stream: S,
    namespace: String,
    service: String,
    ttl_secs: i32,
) -> Result<Lock, RestartError> {
    stream
        .send(AcquireRestartLockRequest {
            namespace,
            service,
            ttl_seconds: ttl_secs,
            heartbeat: false,
        })
        .await?;

    let (token, expires_at) = loop {
        match stream.recv().await? {
            Some(resp) if resp.message_type == MessageType::Acquired as i32 => {
                break (resp.token, resp.expires_at);
            }
            // QUEUE_POSITION (and anything else unexpected) — keep draining
            // until ACQUIRED or the stream ends.
            Some(_) => continue,
            None => return Err(RestartError::ClosedBeforeAcquired),
        }
    };

    let state = Arc::new(StdMutex::new(LockState { token, expires_at }));
    let (lost_tx, lost_rx) = watch::channel(None);
    let (release_tx, release_rx) = oneshot::channel();
    let (done_tx, done_rx) = oneshot::channel();
    let released = Arc::new(AtomicBool::new(false));

    tokio::spawn(run_lock_loop(
        stream,
        ttl_secs,
        state.clone(),
        lost_tx,
        release_rx,
        done_tx,
        released.clone(),
    ));

    Ok(Lock {
        state,
        lost_rx,
        release_tx: StdMutex::new(Some(release_tx)),
        done_rx: StdMutex::new(Some(done_rx)),
        released,
    })
}

/// Owns `stream` for the entire hold duration: sends heartbeats at
/// `ttl_secs/4`, applies `TTL_EXTENDED` acks to the tracked expiry, and
/// detects lock loss (stream error/close) as distinct from an intentional
/// [`Lock::release`] (checked via `released`, which `release()` sets
/// *before* signalling this task, so a release racing a stream error never
/// misreports as a loss).
async fn run_lock_loop<S: LockStream>(
    mut stream: S,
    ttl_secs: i32,
    state: Arc<StdMutex<LockState>>,
    lost_tx: watch::Sender<Option<Arc<RestartError>>>,
    mut release_rx: oneshot::Receiver<()>,
    done_tx: oneshot::Sender<()>,
    released: Arc<AtomicBool>,
) {
    let interval = heartbeat_interval(ttl_secs);
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);

    loop {
        tokio::select! {
            biased;

            _ = &mut release_rx => {
                let _ = stream.close_send().await;
                break;
            }

            _ = ticker.tick() => {
                if let Err(e) = stream.send(AcquireRestartLockRequest {
                    namespace: String::new(),
                    service: String::new(),
                    ttl_seconds: 0,
                    heartbeat: true,
                }).await {
                    report_lost(&lost_tx, &released, e);
                    break;
                }
            }

            recv_result = stream.recv() => {
                match recv_result {
                    Ok(Some(resp)) => {
                        if resp.message_type == MessageType::TtlExtended as i32 {
                            let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
                            guard.expires_at = resp.expires_at;
                        }
                        // ACQUIRED/QUEUE_POSITION shouldn't recur after
                        // acquisition; ignore defensively if they do.
                    }
                    Ok(None) => {
                        report_lost(&lost_tx, &released, RestartError::LockLost("stream closed by server".to_string()));
                        break;
                    }
                    Err(e) => {
                        report_lost(&lost_tx, &released, e);
                        break;
                    }
                }
            }
        }
    }

    let _ = done_tx.send(());
}

fn heartbeat_interval(ttl_secs: i32) -> Duration {
    let ttl = Duration::from_secs(ttl_secs.max(1) as u64);
    let interval = ttl / 4;
    if interval.is_zero() {
        Duration::from_millis(1)
    } else {
        interval
    }
}

fn report_lost(
    lost_tx: &watch::Sender<Option<Arc<RestartError>>>,
    released: &AtomicBool,
    err: RestartError,
) {
    if released.load(Ordering::SeqCst) {
        return;
    }
    let _ = lost_tx.send(Some(Arc::new(err)));
}

// ---------------------------------------------------------------------
// WatchServiceBundle
// ---------------------------------------------------------------------

/// The subset of stream operations [`watch_bundle`] depends on. Mirrors
/// Go's `watchStream` interface.
trait WatchStream: Send {
    fn recv(
        &mut self,
    ) -> impl Future<Output = Result<Option<WatchServiceBundleResponse>, RestartError>> + Send;
}

struct RealWatchStream {
    inbound: tonic::codec::Streaming<WatchServiceBundleResponse>,
}

impl WatchStream for RealWatchStream {
    async fn recv(&mut self) -> Result<Option<WatchServiceBundleResponse>, RestartError> {
        self.inbound
            .message()
            .await
            .map_err(|status| RestartError::Recv(status.to_string()))
    }
}

/// Watches for signet bundle-change notifications for `namespace`/`service`,
/// reconnecting with exponential backoff (1s, doubling, capped at 30s, reset
/// to 1s on any successful receive) if the stream breaks.
///
/// Rapid successive changes are coalesced: the returned receiver only ever
/// signals "at least one change happened since you last received," never a
/// count — it's a bounded (capacity 1) channel filled with a non-blocking
/// `try_send`, so a consumer that hasn't drained the previous signal simply
/// doesn't get a second one queued behind it.
///
/// The background task (and the returned receiver) stops when `cancel` is
/// cancelled.
pub fn watch_bundle(
    client: SecretsServiceClient<Channel>,
    namespace: impl Into<String>,
    service: impl Into<String>,
    cancel: CancellationToken,
) -> mpsc::Receiver<()> {
    let (changes_tx, changes_rx) = mpsc::channel(1);
    let namespace = namespace.into();
    let service = service.into();

    tokio::spawn(async move {
        watch_loop(changes_tx, cancel, move || {
            let mut client = client.clone();
            let namespace = namespace.clone();
            let service = service.clone();
            async move {
                let response = client
                    .watch_service_bundle(WatchServiceBundleRequest { namespace, service })
                    .await
                    .map_err(|status| RestartError::WatchOpen(status.to_string()))?;
                Ok::<_, RestartError>(RealWatchStream {
                    inbound: response.into_inner(),
                })
            }
        })
        .await;
    });

    changes_rx
}

/// The generic core of [`watch_bundle`], tested directly against
/// hand-written [`WatchStream`] fakes (via `open`, mirroring Go's
/// `open func() (watchStream, error)`).
async fn watch_loop<S, F, Fut>(changes: mpsc::Sender<()>, cancel: CancellationToken, mut open: F)
where
    S: WatchStream + Send + 'static,
    F: FnMut() -> Fut + Send,
    Fut: Future<Output = Result<S, RestartError>> + Send,
{
    let mut backoff = WATCH_BACKOFF_MIN;

    loop {
        if cancel.is_cancelled() {
            return;
        }

        let mut stream = match open().await {
            Ok(stream) => stream,
            Err(_) => {
                if !sleep_or_cancelled(backoff, &cancel).await {
                    return;
                }
                backoff = next_backoff(backoff);
                continue;
            }
        };

        loop {
            tokio::select! {
                () = cancel.cancelled() => return,
                recv_result = stream.recv() => {
                    match recv_result {
                        Ok(Some(resp)) => {
                            backoff = WATCH_BACKOFF_MIN;
                            if resp.event_type == EventType::Changed as i32 {
                                let _ = changes.try_send(());
                            }
                        }
                        _ => break, // error, or a clean stream end -> reconnect
                    }
                }
            }
        }

        if cancel.is_cancelled() {
            return;
        }
        if !sleep_or_cancelled(backoff, &cancel).await {
            return;
        }
        backoff = next_backoff(backoff);
    }
}

fn next_backoff(current: Duration) -> Duration {
    let doubled = current.saturating_mul(2);
    if doubled > WATCH_BACKOFF_MAX {
        WATCH_BACKOFF_MAX
    } else {
        doubled
    }
}

/// Waits for `d` or `cancel`, whichever comes first. Returns `false` if
/// cancelled, `true` if the sleep completed normally.
async fn sleep_or_cancelled(d: Duration, cancel: &CancellationToken) -> bool {
    tokio::select! {
        () = cancel.cancelled() => false,
        () = tokio::time::sleep(d) => true,
    }
}

// ---------------------------------------------------------------------
// WaitForRestart
// ---------------------------------------------------------------------

/// Combines [`watch_bundle`] and [`acquire_lock`]: waits for the next bundle
/// change (debounced by `debounce` — zero means act on the first event
/// immediately), then acquires the restart lock, returning once held.
///
/// This does **not** fetch the updated bundle: since this call doesn't spawn
/// a replacement process, the next process instance fetches it fresh during
/// its own normal startup. See the crate README's "Coordinated restarts"
/// section for the full rationale.
///
/// Typical caller shape:
///
/// ```no_run
/// # use std::time::Duration;
/// # use tokio_util::sync::CancellationToken;
/// # use signet_client::{wait_for_restart, signet::v1::secrets_service_client::SecretsServiceClient};
/// # async fn example(client: SecretsServiceClient<tonic::transport::Channel>) -> Result<(), Box<dyn std::error::Error>> {
/// let lock = wait_for_restart(
///     client, "default", "example",
///     Duration::from_secs(30), // lock TTL — must cover your graceful shutdown
///     Duration::from_secs(10), // debounce — absorb rapid successive changes
///     CancellationToken::new(),
/// ).await?;
/// // ... your own graceful shutdown: drain in-flight requests, close resources ...
/// lock.release().await?;
/// std::process::exit(0); // Kubernetes restarts the pod; the new process fetches fresh config
/// # Ok(())
/// # }
/// ```
pub async fn wait_for_restart(
    client: SecretsServiceClient<Channel>,
    namespace: impl Into<String>,
    service: impl Into<String>,
    ttl: Duration,
    debounce: Duration,
    cancel: CancellationToken,
) -> Result<Lock, RestartError> {
    let namespace = namespace.into();
    let service = service.into();

    let mut changes = watch_bundle(client.clone(), namespace.clone(), service.clone(), cancel.clone());

    if changes.recv().await.is_none() {
        return Err(RestartError::WatchStopped);
    }

    if !debounce.is_zero() {
        let sleep = tokio::time::sleep(debounce);
        tokio::pin!(sleep);

        loop {
            tokio::select! {
                maybe_change = changes.recv() => {
                    match maybe_change {
                        Some(()) => sleep.as_mut().reset(tokio::time::Instant::now() + debounce),
                        None => return Err(RestartError::WatchStopped),
                    }
                }
                () = &mut sleep => break,
                () = cancel.cancelled() => return Err(RestartError::Cancelled),
            }
        }
    }

    acquire_lock(client, namespace, service, ttl).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;
    use tonic::transport::Endpoint;

    // ---- AcquireRestartLock fakes ----

    enum LockRecvResult {
        Resp(AcquireRestartLockResponse),
        Err(RestartError),
    }

    struct FakeLockStream {
        rx: mpsc::UnboundedReceiver<LockRecvResult>,
        sent: Arc<StdMutex<Vec<AcquireRestartLockRequest>>>,
        closed: Arc<AtomicBool>,
    }

    impl LockStream for FakeLockStream {
        async fn send(&mut self, req: AcquireRestartLockRequest) -> Result<(), RestartError> {
            if self.closed.load(Ordering::SeqCst) {
                return Err(RestartError::Send("send on closed stream".to_string()));
            }
            self.sent.lock().unwrap().push(req);
            Ok(())
        }

        async fn recv(&mut self) -> Result<Option<AcquireRestartLockResponse>, RestartError> {
            if self.closed.load(Ordering::SeqCst) {
                return Err(RestartError::Recv("stream closed".to_string()));
            }
            match self.rx.recv().await {
                Some(LockRecvResult::Resp(r)) => Ok(Some(r)),
                Some(LockRecvResult::Err(e)) => Err(e),
                None => Err(RestartError::Recv("stream closed".to_string())),
            }
        }

        async fn close_send(&mut self) -> Result<(), RestartError> {
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    struct FakeLockHandle {
        tx: mpsc::UnboundedSender<LockRecvResult>,
        sent: Arc<StdMutex<Vec<AcquireRestartLockRequest>>>,
        #[allow(dead_code)]
        closed: Arc<AtomicBool>,
    }

    impl FakeLockHandle {
        fn new() -> (FakeLockStream, Self) {
            let (tx, rx) = mpsc::unbounded_channel();
            let sent = Arc::new(StdMutex::new(Vec::new()));
            let closed = Arc::new(AtomicBool::new(false));
            (
                FakeLockStream {
                    rx,
                    sent: sent.clone(),
                    closed: closed.clone(),
                },
                Self { tx, sent, closed },
            )
        }

        fn push_resp(&self, resp: AcquireRestartLockResponse) {
            let _ = self.tx.send(LockRecvResult::Resp(resp));
        }

        fn push_err(&self, err: RestartError) {
            let _ = self.tx.send(LockRecvResult::Err(err));
        }

        fn sent_count(&self) -> usize {
            self.sent.lock().unwrap().len()
        }
    }

    fn acquired_resp(token: &str, expires_at_secs_from_now: i64) -> AcquireRestartLockResponse {
        AcquireRestartLockResponse {
            message_type: MessageType::Acquired as i32,
            position: 0,
            token: token.to_string(),
            expires_at: Some(future_timestamp(expires_at_secs_from_now)),
        }
    }

    fn queue_position_resp(position: i32) -> AcquireRestartLockResponse {
        AcquireRestartLockResponse {
            message_type: MessageType::QueuePosition as i32,
            position,
            token: String::new(),
            expires_at: None,
        }
    }

    fn ttl_extended_resp(expires_at_secs_from_now: i64) -> AcquireRestartLockResponse {
        AcquireRestartLockResponse {
            message_type: MessageType::TtlExtended as i32,
            position: 0,
            token: String::new(),
            expires_at: Some(future_timestamp(expires_at_secs_from_now)),
        }
    }

    fn future_timestamp(secs_from_now: i64) -> prost_types::Timestamp {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        prost_types::Timestamp {
            seconds: now.as_secs() as i64 + secs_from_now,
            nanos: 0,
        }
    }

    #[tokio::test]
    async fn acquire_lock_rejects_ttl_zero_before_opening_any_stream() {
        // `Endpoint::connect_lazy` never dials, so if `acquire_lock` really
        // validates ttl before touching the stream, this returns instantly
        // without any network activity.
        let channel = Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
        let client = SecretsServiceClient::new(channel);

        let err = acquire_lock(client, "ns", "svc", Duration::ZERO)
            .await
            .unwrap_err();
        assert!(
            matches!(err, RestartError::InvalidTtl(_)),
            "expected InvalidTtl, got {err:?}"
        );
        assert!(err.to_string().contains("ttl must be > 0"));
    }

    #[test]
    fn validate_ttl_rejects_zero() {
        let err = validate_ttl(Duration::ZERO).unwrap_err();
        assert!(matches!(err, RestartError::InvalidTtl(_)));
    }

    #[test]
    fn validate_ttl_floors_sub_second_ttl_to_one_second() {
        assert_eq!(validate_ttl(Duration::from_millis(500)).unwrap(), 1);
    }

    #[test]
    fn validate_ttl_truncates_like_go_int32_division() {
        assert_eq!(validate_ttl(Duration::from_millis(4999)).unwrap(), 4);
    }

    #[tokio::test]
    async fn acquire_lock_queue_position_then_acquired() {
        let (stream, handle) = FakeLockHandle::new();
        handle.push_resp(queue_position_resp(2));
        handle.push_resp(queue_position_resp(1));
        handle.push_resp(acquired_resp("tok-1", 30));

        let lock = acquire_lock_with(stream, "ns".to_string(), "svc".to_string(), 4)
            .await
            .expect("acquire_lock_with");

        assert_eq!(lock.token(), "tok-1");
        assert_eq!(handle.sent_count(), 1, "expected exactly 1 initial send before any heartbeat");

        lock.release().await.unwrap();
    }

    #[tokio::test]
    async fn acquire_lock_stream_error_before_acquired_surfaces_as_err() {
        let (stream, handle) = FakeLockHandle::new();
        handle.push_err(RestartError::Recv("boom".to_string()));

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            acquire_lock_with(stream, "ns".to_string(), "svc".to_string(), 4),
        )
        .await
        .expect("acquire_lock_with should not hang");

        let err = result.unwrap_err();
        assert!(err.to_string().contains("boom"));
    }

    #[tokio::test]
    async fn acquire_lock_stream_closed_before_acquired_is_a_clear_error() {
        let (stream, handle) = FakeLockHandle::new();
        drop(handle); // drop the sender half without pushing anything -> recv() sees a closed channel

        let err = acquire_lock_with(stream, "ns".to_string(), "svc".to_string(), 4)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("stream closed"));
    }

    #[tokio::test]
    async fn heartbeat_interval_is_ttl_over_four() {
        // ttl=800ms => heartbeat interval = 200ms.
        let (stream, handle) = FakeLockHandle::new();
        handle.push_resp(acquired_resp("tok-1", 4));

        // validate_ttl only ever produces whole seconds from a Duration, but
        // run_lock_loop's cadence is computed straight from ttl_secs, so we
        // can exercise sub-second cadence directly via acquire_lock_with's
        // ttl_secs parameter without going through validate_ttl. Here we use
        // ttl_secs=1 (=> 250ms interval) for a fast, still-comfortably-above
        // scheduling-noise test.
        let lock = acquire_lock_with(stream, "ns".to_string(), "svc".to_string(), 1)
            .await
            .expect("acquire_lock_with");

        tokio::time::sleep(Duration::from_millis(650)).await;

        // 250ms interval, ~650ms elapsed => expect >=2 heartbeats (in
        // addition to the 1 initial request).
        let sent = handle.sent_count();
        assert!(sent >= 3, "sent_count={sent}, want >= 3 (1 initial + >=2 heartbeats)");

        lock.release().await.unwrap();
    }

    #[tokio::test]
    async fn ttl_extended_updates_expires_at() {
        let (stream, handle) = FakeLockHandle::new();
        handle.push_resp(acquired_resp("tok-1", 4));

        let lock = acquire_lock_with(stream, "ns".to_string(), "svc".to_string(), 4)
            .await
            .expect("acquire_lock_with");

        let extended = future_timestamp(60);
        handle.push_resp(ttl_extended_resp(60));

        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            if lock.expires_at().as_ref().map(|t| t.seconds) == Some(extended.seconds) {
                break;
            }
            if tokio::time::Instant::now() > deadline {
                panic!(
                    "expires_at never reflected TTL_EXTENDED; last = {:?}, want seconds = {}",
                    lock.expires_at(),
                    extended.seconds
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        lock.release().await.unwrap();
    }

    #[tokio::test]
    async fn release_is_idempotent() {
        let (stream, handle) = FakeLockHandle::new();
        handle.push_resp(acquired_resp("tok-1", 30));

        let lock = acquire_lock_with(stream, "ns".to_string(), "svc".to_string(), 4)
            .await
            .expect("acquire_lock_with");

        lock.release().await.expect("first release");
        lock.release().await.expect("second release should be a no-op");
    }

    #[tokio::test]
    async fn lost_reported_on_unexpected_stream_error() {
        let (stream, handle) = FakeLockHandle::new();
        handle.push_resp(acquired_resp("tok-1", 4));

        let lock = acquire_lock_with(stream, "ns".to_string(), "svc".to_string(), 4)
            .await
            .expect("acquire_lock_with");

        handle.push_err(RestartError::Recv("lock lost".to_string()));

        let mut lost = lock.lost();
        tokio::time::timeout(Duration::from_secs(2), lost.changed())
            .await
            .expect("Lost() never signaled after stream error")
            .expect("watch sender dropped unexpectedly");
        let got = lost.borrow().clone();
        assert!(got.is_some(), "expected Some(err) on Lost()");
    }

    #[tokio::test]
    async fn release_does_not_report_lost() {
        let (stream, handle) = FakeLockHandle::new();
        handle.push_resp(acquired_resp("tok-1", 30));

        let lock = acquire_lock_with(stream, "ns".to_string(), "svc".to_string(), 4)
            .await
            .expect("acquire_lock_with");

        // `release()` only returns once the background task has fully
        // unwound (it awaits `done_rx`, sent as literally the task's last
        // action), so by the time we get here no further writes to the
        // `lost` watch channel are possible — checking the stored value
        // directly is deterministic. (An earlier version of this test raced
        // `lost.changed()` against a timeout, which is *not* deterministic:
        // the background task's `watch::Sender` is dropped when the task
        // exits, and a dropped sender makes `changed()` resolve immediately
        // with `Err`, indistinguishable at the `Result` level from "really
        // did change" without inspecting the value too.)
        lock.release().await.expect("release");

        assert!(
            lock.lost().borrow().is_none(),
            "Lost() recorded a value after a clean release: {:?}",
            lock.lost().borrow()
        );
    }

    #[tokio::test]
    async fn lost_is_none_immediately_after_acquire() {
        // A caller polling (rather than awaiting `.changed()`) should see a
        // clean `None` before anything goes wrong.
        let (stream, handle) = FakeLockHandle::new();
        handle.push_resp(acquired_resp("tok-1", 30));

        let lock = acquire_lock_with(stream, "ns".to_string(), "svc".to_string(), 4)
            .await
            .expect("acquire_lock_with");

        assert!(lock.lost().borrow().is_none());
        lock.release().await.unwrap();
    }

    // ---- WatchServiceBundle fakes ----

    struct FakeWatchStream {
        rx: mpsc::UnboundedReceiver<Result<WatchServiceBundleResponse, RestartError>>,
        recv_count: Arc<AtomicUsize>,
    }

    impl WatchStream for FakeWatchStream {
        async fn recv(&mut self) -> Result<Option<WatchServiceBundleResponse>, RestartError> {
            self.recv_count.fetch_add(1, Ordering::SeqCst);
            match self.rx.recv().await {
                Some(Ok(r)) => Ok(Some(r)),
                Some(Err(e)) => Err(e),
                None => Err(RestartError::Recv("stream closed".to_string())),
            }
        }
    }

    fn changed_resp() -> WatchServiceBundleResponse {
        WatchServiceBundleResponse {
            event_type: EventType::Changed as i32,
            namespace: "ns".to_string(),
            service: "svc".to_string(),
        }
    }

    #[tokio::test]
    async fn watch_loop_coalesces_rapid_changes() {
        let (tx, rx) = mpsc::unbounded_channel();
        let recv_count = Arc::new(AtomicUsize::new(0));
        for _ in 0..3 {
            tx.send(Ok(changed_resp())).unwrap();
        }
        let stream = FakeWatchStream {
            rx,
            recv_count: recv_count.clone(),
        };

        let (changes_tx, mut changes_rx) = mpsc::channel(1);
        let cancel = CancellationToken::new();
        let cancel_for_loop = cancel.clone();

        let streams = Arc::new(tokio::sync::Mutex::new(VecDeque::from(vec![stream])));
        let handle = tokio::spawn(async move {
            watch_loop(changes_tx, cancel_for_loop, move || {
                let streams = streams.clone();
                async move {
                    streams
                        .lock()
                        .await
                        .pop_front()
                        .ok_or_else(|| RestartError::WatchOpen("no more fake streams".to_string()))
                }
            })
            .await;
        });

        // Wait until watch_loop has drained all 3 pushed events (the 4th
        // Recv call is the one that blocks) before checking coalescing —
        // otherwise this is racy: consuming the first signal before all 3
        // are processed just frees the buffer for a legitimately new one.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while recv_count.load(Ordering::SeqCst) < 4 {
            if tokio::time::Instant::now() > deadline {
                panic!(
                    "watch_loop only issued {} Recv calls, want >= 4",
                    recv_count.load(Ordering::SeqCst)
                );
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        assert_eq!(changes_rx.len(), 1, "expected exactly 1 coalesced signal after 3 rapid changes");

        changes_rx.recv().await.expect("one coalesced change");
        assert!(
            changes_rx.try_recv().is_err(),
            "expected no further pending signal after draining the coalesced one"
        );

        cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn watch_loop_reconnects_after_stream_error() {
        let (first_tx, first_rx) = mpsc::unbounded_channel();
        let first_recv_count = Arc::new(AtomicUsize::new(0));
        first_tx.send(Err(RestartError::Recv("boom".to_string()))).unwrap();
        let first = FakeWatchStream {
            rx: first_rx,
            recv_count: first_recv_count,
        };

        let (second_tx, second_rx) = mpsc::unbounded_channel();
        let second_recv_count = Arc::new(AtomicUsize::new(0));
        second_tx.send(Ok(changed_resp())).unwrap();
        let second = FakeWatchStream {
            rx: second_rx,
            recv_count: second_recv_count,
        };

        let (changes_tx, mut changes_rx) = mpsc::channel(1);
        let cancel = CancellationToken::new();
        let cancel_for_loop = cancel.clone();

        let streams = Arc::new(tokio::sync::Mutex::new(VecDeque::from(vec![first, second])));
        let handle = tokio::spawn(async move {
            watch_loop(changes_tx, cancel_for_loop, move || {
                let streams = streams.clone();
                async move {
                    streams
                        .lock()
                        .await
                        .pop_front()
                        .ok_or_else(|| RestartError::WatchOpen("no more fake streams".to_string()))
                }
            })
            .await;
        });

        tokio::time::timeout(Duration::from_secs(4), changes_rx.recv())
            .await
            .expect("expected watch_loop to reconnect and eventually deliver a change")
            .expect("changes channel closed unexpectedly");

        cancel.cancel();
        let _ = handle.await;
    }

    #[test]
    fn next_backoff_doubles_and_caps() {
        assert_eq!(next_backoff(Duration::from_secs(1)), Duration::from_secs(2));
        assert_eq!(next_backoff(Duration::from_secs(16)), Duration::from_secs(30));
        assert_eq!(next_backoff(Duration::from_secs(30)), Duration::from_secs(30));
    }
}
