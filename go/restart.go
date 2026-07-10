package signet

import (
	"context"
	"fmt"
	"sync"
	"time"

	signetv1 "github.com/bytepunx/signet-clients/go/gen/signet/v1"
)

const (
	watchBackoffMin = 1 * time.Second
	watchBackoffMax = 30 * time.Second
)

// lockStream is the subset of signetv1.SecretsService_AcquireRestartLockClient
// that AcquireLock depends on, so tests can substitute a fake instead of a
// real gRPC stream.
type lockStream interface {
	Send(*signetv1.AcquireRestartLockRequest) error
	Recv() (*signetv1.AcquireRestartLockResponse, error)
	CloseSend() error
}

// watchStream is the subset of signetv1.SecretsService_WatchServiceBundleClient
// that WatchBundle depends on.
type watchStream interface {
	Recv() (*signetv1.WatchServiceBundleResponse, error)
}

// WatchBundle watches for signet bundle-change notifications for
// namespace/service, reconnecting with exponential backoff (1s, doubling,
// capped at 30s, reset to 1s on any successful receive) if the stream
// breaks. Rapid successive changes are coalesced: the returned channel only
// signals "at least one change happened since you last received," never a
// count. The channel is closed when ctx is done.
func WatchBundle(ctx context.Context, client signetv1.SecretsServiceClient, namespace, service string) <-chan struct{} {
	changes := make(chan struct{}, 1)
	go watchLoop(ctx, changes, func() (watchStream, error) {
		return client.WatchServiceBundle(ctx, &signetv1.WatchServiceBundleRequest{
			Namespace: namespace,
			Service:   service,
		})
	})
	return changes
}

func watchLoop(ctx context.Context, changes chan<- struct{}, open func() (watchStream, error)) {
	defer close(changes)

	backoff := watchBackoffMin
	for {
		if ctx.Err() != nil {
			return
		}

		stream, err := open()
		if err != nil {
			if !sleepOrDone(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}

		for {
			resp, err := stream.Recv()
			if err != nil {
				break
			}
			backoff = watchBackoffMin
			if resp.GetEventType() == signetv1.WatchServiceBundleResponse_EVENT_TYPE_CHANGED {
				select {
				case changes <- struct{}{}:
				default:
					// already have a pending unread change signal; coalesce
				}
			}
		}

		if ctx.Err() != nil {
			return
		}
		if !sleepOrDone(ctx, backoff) {
			return
		}
		backoff = nextBackoff(backoff)
	}
}

func nextBackoff(cur time.Duration) time.Duration {
	next := cur * 2
	if next > watchBackoffMax {
		return watchBackoffMax
	}
	return next
}

// sleepOrDone waits for d or ctx cancellation, whichever comes first. It
// returns false if ctx was done, true if the sleep completed normally.
func sleepOrDone(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Lock represents a held signet restart lock. Call Release once your own
// graceful shutdown (draining in-flight work, closing resources) is
// complete, immediately before exiting.
type Lock struct {
	stream lockStream

	mu        sync.Mutex
	token     string
	expiresAt time.Time
	released  bool

	lost       chan error
	lostOnce   sync.Once
	cancelHB   context.CancelFunc
	recvDoneCh chan struct{}
}

// Token identifies this lock acquisition, for audit/logging purposes.
func (l *Lock) Token() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.token
}

// ExpiresAt returns the lock's current expiry, updated as heartbeats are
// acknowledged.
func (l *Lock) ExpiresAt() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.expiresAt
}

// Lost reports, at most once, an error if the lock is lost unexpectedly
// (stream error, or the server closing the stream) before Release is
// called. The caller should treat this as "another replica may now acquire
// and restart concurrently" — there is nothing to undo, only to log.
func (l *Lock) Lost() <-chan error {
	return l.lost
}

// Release closes the lock stream, releasing the lock for the next waiting
// replica. Safe to call once; idempotent.
func (l *Lock) Release() error {
	l.mu.Lock()
	if l.released {
		l.mu.Unlock()
		return nil
	}
	l.released = true
	l.mu.Unlock()

	l.cancelHB()
	err := l.stream.CloseSend()
	<-l.recvDoneCh // wait for the recv loop to observe the close and exit
	return err
}

func (l *Lock) reportLost(err error) {
	l.mu.Lock()
	released := l.released
	l.mu.Unlock()
	if released || err == nil {
		return
	}
	l.lostOnce.Do(func() {
		select {
		case l.lost <- err:
		default:
		}
	})
}

// AcquireLock blocks until this replica acquires signet's restart lock for
// namespace/service, queueing behind any current holder. ttl must be > 0
// and must cover the full time between acquiring the lock and calling
// Lock.Release — signet has no server-side default. Heartbeats are sent
// automatically at ttl/4 (signet's documented convention: 4 consecutive
// missed heartbeats exhaust the TTL) until Release is called, ctx is done,
// or the lock is lost (see Lock.Lost).
func AcquireLock(ctx context.Context, client signetv1.SecretsServiceClient, namespace, service string, ttl time.Duration) (*Lock, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("signet: ttl must be > 0, got %s", ttl)
	}

	stream, err := client.AcquireRestartLock(ctx)
	if err != nil {
		return nil, fmt.Errorf("signet: open AcquireRestartLock stream: %w", err)
	}
	return acquireLock(ctx, stream, namespace, service, ttl)
}

func acquireLock(ctx context.Context, stream lockStream, namespace, service string, ttl time.Duration) (*Lock, error) {
	ttlSecs := int32(ttl / time.Second)
	if ttlSecs <= 0 {
		ttlSecs = 1
	}

	if err := stream.Send(&signetv1.AcquireRestartLockRequest{
		Namespace:  namespace,
		Service:    service,
		TtlSeconds: ttlSecs,
	}); err != nil {
		return nil, fmt.Errorf("signet: send initial AcquireRestartLock request: %w", err)
	}

	hbCtx, cancelHB := context.WithCancel(ctx)
	l := &Lock{
		stream:     stream,
		lost:       make(chan error, 1),
		cancelHB:   cancelHB,
		recvDoneCh: make(chan struct{}),
	}

	acquired := make(chan error, 1)
	go recvLoop(l, acquired)

	select {
	case err := <-acquired:
		if err != nil {
			cancelHB()
			return nil, err
		}
	case <-ctx.Done():
		cancelHB()
		return nil, ctx.Err()
	}

	go heartbeatLoop(hbCtx, l, ttlSecs)

	return l, nil
}

// recvLoop owns Recv() for the stream's entire lifetime: it delivers the
// first ACQUIRED (or a fatal error before it) to acquired, then keeps
// reading TTL_EXTENDED acks (updating expiresAt) until the stream errors or
// closes, at which point it reports loss via l.Lost (unless Release already
// initiated the close).
func recvLoop(l *Lock, acquired chan<- error) {
	defer close(l.recvDoneCh)

	gotAcquired := false
	for {
		resp, err := l.stream.Recv()
		if err != nil {
			if !gotAcquired {
				acquired <- err
			} else {
				l.reportLost(err)
			}
			return
		}

		switch resp.GetMessageType() {
		case signetv1.AcquireRestartLockResponse_MESSAGE_TYPE_ACQUIRED:
			l.mu.Lock()
			l.token = resp.GetToken()
			if ts := resp.GetExpiresAt(); ts != nil {
				l.expiresAt = ts.AsTime()
			}
			l.mu.Unlock()
			if !gotAcquired {
				gotAcquired = true
				acquired <- nil
			}
		case signetv1.AcquireRestartLockResponse_MESSAGE_TYPE_TTL_EXTENDED:
			l.mu.Lock()
			if ts := resp.GetExpiresAt(); ts != nil {
				l.expiresAt = ts.AsTime()
			}
			l.mu.Unlock()
		case signetv1.AcquireRestartLockResponse_MESSAGE_TYPE_QUEUE_POSITION:
			// no state to update; callers who want position visibility can
			// wrap AcquireLock and race their own Recv against the exposed
			// primitives if that becomes a real need.
		}
	}
}

func heartbeatLoop(ctx context.Context, l *Lock, ttlSecs int32) {
	interval := time.Duration(ttlSecs) * time.Second / 4
	if interval <= 0 {
		interval = 1
	}
	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := l.stream.Send(&signetv1.AcquireRestartLockRequest{Heartbeat: true}); err != nil {
				l.reportLost(err)
				return
			}
		}
	}
}

// WaitForRestart is a convenience combining WatchBundle and AcquireLock: it
// waits for the next bundle change (debounced by debounce — 0 means act on
// the first event immediately), then acquires the restart lock, returning
// once held. It does not fetch the updated bundle: since this call doesn't
// spawn a replacement process, the next process instance fetches it fresh
// during its own normal startup.
//
// Typical caller shape:
//
//	lock, err := signet.WaitForRestart(ctx, client, ns, svc, 30*time.Second, 10*time.Second)
//	// ... graceful shutdown: drain in-flight requests, close resources ...
//	lock.Release()
//	os.Exit(0)
func WaitForRestart(ctx context.Context, client signetv1.SecretsServiceClient, namespace, service string, ttl, debounce time.Duration) (*Lock, error) {
	changes := WatchBundle(ctx, client, namespace, service)

	if _, ok := <-changes; !ok {
		return nil, ctx.Err()
	}

	if debounce > 0 {
		timer := time.NewTimer(debounce)
		defer timer.Stop()
	debounceLoop:
		for {
			select {
			case _, ok := <-changes:
				if !ok {
					return nil, ctx.Err()
				}
				if !timer.Stop() {
					<-timer.C
				}
				timer.Reset(debounce)
			case <-timer.C:
				break debounceLoop
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	return AcquireLock(ctx, client, namespace, service, ttl)
}
