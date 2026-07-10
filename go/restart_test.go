package signet

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	signetv1 "github.com/bytepunx/signet-clients/go/gen/signet/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeLockStream is a hand-written fake satisfying lockStream, driven by a
// scripted sequence of responses (or errors) fed to Recv, and recording
// every Send for assertions.
type fakeLockStream struct {
	mu        sync.Mutex
	responses chan lockRecvResult
	sent      []*signetv1.AcquireRestartLockRequest
	closed    bool
}

type lockRecvResult struct {
	resp *signetv1.AcquireRestartLockResponse
	err  error
}

func newFakeLockStream(buf int) *fakeLockStream {
	return &fakeLockStream{responses: make(chan lockRecvResult, buf)}
}

func (f *fakeLockStream) pushResp(resp *signetv1.AcquireRestartLockResponse) {
	f.responses <- lockRecvResult{resp: resp}
}

func (f *fakeLockStream) pushErr(err error) {
	f.responses <- lockRecvResult{err: err}
}

func (f *fakeLockStream) Send(req *signetv1.AcquireRestartLockRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return errors.New("send on closed stream")
	}
	f.sent = append(f.sent, req)
	return nil
}

func (f *fakeLockStream) Recv() (*signetv1.AcquireRestartLockResponse, error) {
	r, ok := <-f.responses
	if !ok {
		return nil, errors.New("stream closed")
	}
	return r.resp, r.err
}

func (f *fakeLockStream) CloseSend() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	close(f.responses)
	return nil
}

func (f *fakeLockStream) sentCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

func acquiredResp(token string, expiresAt time.Time) *signetv1.AcquireRestartLockResponse {
	return &signetv1.AcquireRestartLockResponse{
		MessageType: signetv1.AcquireRestartLockResponse_MESSAGE_TYPE_ACQUIRED,
		Token:       token,
		ExpiresAt:   timestamppb.New(expiresAt),
	}
}

func queuePositionResp(pos int32) *signetv1.AcquireRestartLockResponse {
	return &signetv1.AcquireRestartLockResponse{
		MessageType: signetv1.AcquireRestartLockResponse_MESSAGE_TYPE_QUEUE_POSITION,
		Position:    pos,
	}
}

func ttlExtendedResp(expiresAt time.Time) *signetv1.AcquireRestartLockResponse {
	return &signetv1.AcquireRestartLockResponse{
		MessageType: signetv1.AcquireRestartLockResponse_MESSAGE_TYPE_TTL_EXTENDED,
		ExpiresAt:   timestamppb.New(expiresAt),
	}
}

func TestAcquireLock_RejectsNonPositiveTTL(t *testing.T) {
	if _, err := AcquireLock(context.Background(), nil, "ns", "svc", 0); err == nil {
		t.Fatal("expected error for ttl <= 0")
	}
	if _, err := AcquireLock(context.Background(), nil, "ns", "svc", -1); err == nil {
		t.Fatal("expected error for negative ttl")
	}
}

func TestAcquireLock_QueuePositionThenAcquired(t *testing.T) {
	stream := newFakeLockStream(4)
	stream.pushResp(queuePositionResp(2))
	stream.pushResp(queuePositionResp(1))
	stream.pushResp(acquiredResp("tok-1", time.Now().Add(30*time.Second)))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lock, err := acquireLock(ctx, stream, "ns", "svc", 4*time.Second)
	if err != nil {
		t.Fatalf("acquireLock: %v", err)
	}
	defer lock.Release()

	if lock.Token() != "tok-1" {
		t.Errorf("Token() = %q, want tok-1", lock.Token())
	}
	if stream.sentCount() != 1 {
		t.Errorf("expected exactly 1 initial send before heartbeats, got %d", stream.sentCount())
	}
}

func TestAcquireLock_StreamErrorBeforeAcquired(t *testing.T) {
	stream := newFakeLockStream(4)
	wantErr := errors.New("boom")
	stream.pushErr(wantErr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := acquireLock(ctx, stream, "ns", "svc", 4*time.Second)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAcquireLock_HeartbeatIntervalIsTTLOverFour(t *testing.T) {
	stream := newFakeLockStream(4)
	stream.pushResp(acquiredResp("tok-1", time.Now().Add(4*time.Second)))

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// ttl=4s => heartbeat interval = 1s. Wait ~2.5s and expect >=2 heartbeats
	// sent (in addition to the 1 initial request).
	lock, err := acquireLock(ctx, stream, "ns", "svc", 4*time.Second)
	if err != nil {
		t.Fatalf("acquireLock: %v", err)
	}
	defer lock.Release()

	time.Sleep(2500 * time.Millisecond)
	if got := stream.sentCount(); got < 3 { // 1 initial + >=2 heartbeats
		t.Errorf("sentCount() = %d, want >= 3 (1 initial + >=2 heartbeats at ~1s interval)", got)
	}
}

func TestLock_TTLExtendedUpdatesExpiresAt(t *testing.T) {
	stream := newFakeLockStream(4)
	first := time.Now().Add(4 * time.Second)
	stream.pushResp(acquiredResp("tok-1", first))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lock, err := acquireLock(ctx, stream, "ns", "svc", 4*time.Second)
	if err != nil {
		t.Fatalf("acquireLock: %v", err)
	}
	defer lock.Release()

	extended := time.Now().Add(60 * time.Second)
	stream.pushResp(ttlExtendedResp(extended))

	deadline := time.After(2 * time.Second)
	for {
		if lock.ExpiresAt().Equal(extended) {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("ExpiresAt() never reflected TTL_EXTENDED; last = %v, want %v", lock.ExpiresAt(), extended)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestLock_ReleaseIsIdempotent(t *testing.T) {
	stream := newFakeLockStream(4)
	stream.pushResp(acquiredResp("tok-1", time.Now().Add(30*time.Second)))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lock, err := acquireLock(ctx, stream, "ns", "svc", 4*time.Second)
	if err != nil {
		t.Fatalf("acquireLock: %v", err)
	}

	if err := lock.Release(); err != nil {
		t.Fatalf("first Release: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("second Release should be a no-op, got: %v", err)
	}
}

func TestLock_LostReportedOnUnexpectedStreamError(t *testing.T) {
	stream := newFakeLockStream(4)
	stream.pushResp(acquiredResp("tok-1", time.Now().Add(4*time.Second)))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lock, err := acquireLock(ctx, stream, "ns", "svc", 4*time.Second)
	if err != nil {
		t.Fatalf("acquireLock: %v", err)
	}
	defer lock.Release()

	wantErr := errors.New("lock lost")
	stream.pushErr(wantErr)

	select {
	case err := <-lock.Lost():
		if err == nil {
			t.Fatal("expected non-nil error on Lost()")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Lost() never signaled after stream error")
	}
}

func TestLock_ReleaseDoesNotReportLost(t *testing.T) {
	stream := newFakeLockStream(4)
	stream.pushResp(acquiredResp("tok-1", time.Now().Add(30*time.Second)))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lock, err := acquireLock(ctx, stream, "ns", "svc", 4*time.Second)
	if err != nil {
		t.Fatalf("acquireLock: %v", err)
	}

	if err := lock.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}

	select {
	case err := <-lock.Lost():
		t.Fatalf("Lost() fired after a clean Release: %v", err)
	case <-time.After(200 * time.Millisecond):
		// expected: no loss signal for an intentional release
	}
}

// fakeWatchStream is a hand-written fake satisfying watchStream.
type fakeWatchStream struct {
	responses chan lockRecvResult2

	mu        sync.Mutex
	recvCount int
}

type lockRecvResult2 struct {
	resp *signetv1.WatchServiceBundleResponse
	err  error
}

func newFakeWatchStream(buf int) *fakeWatchStream {
	return &fakeWatchStream{responses: make(chan lockRecvResult2, buf)}
}

func (f *fakeWatchStream) pushChanged() {
	f.responses <- lockRecvResult2{resp: &signetv1.WatchServiceBundleResponse{
		EventType: signetv1.WatchServiceBundleResponse_EVENT_TYPE_CHANGED,
	}}
}

func (f *fakeWatchStream) pushErr(err error) {
	f.responses <- lockRecvResult2{err: err}
}

func (f *fakeWatchStream) recvCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.recvCount
}

func (f *fakeWatchStream) Recv() (*signetv1.WatchServiceBundleResponse, error) {
	f.mu.Lock()
	f.recvCount++
	f.mu.Unlock()

	r, ok := <-f.responses
	if !ok {
		return nil, errors.New("stream closed")
	}
	return r.resp, r.err
}

func TestWatchLoop_CoalescesRapidChanges(t *testing.T) {
	// 3 changes are pushed but the response channel is never closed, so
	// after they're drained the 4th Recv() call just blocks — no error, no
	// reconnect, so open() is only ever called once.
	stream := newFakeWatchStream(8)
	stream.pushChanged()
	stream.pushChanged()
	stream.pushChanged()

	changes := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go watchLoop(ctx, changes, func() (watchStream, error) {
		return stream, nil
	})

	// Wait until watchLoop has actually drained all 3 pushed events (the
	// 4th Recv call is the one that blocks) before checking coalescing —
	// otherwise this is racy: consuming the first signal before all 3 are
	// processed just frees the buffer for a legitimately new one.
	deadline := time.After(2 * time.Second)
	for stream.recvCalls() < 4 {
		select {
		case <-deadline:
			t.Fatalf("watchLoop only issued %d Recv calls, want >= 4", stream.recvCalls())
		case <-time.After(5 * time.Millisecond):
		}
	}

	if n := len(changes); n != 1 {
		t.Fatalf("len(changes) = %d after 3 rapid changes, want exactly 1 (coalesced)", n)
	}

	<-changes
	select {
	case <-changes:
		t.Fatal("expected no further pending signal after draining the coalesced one")
	default:
	}
}

func TestWatchLoop_ReconnectsAfterStreamError(t *testing.T) {
	first := newFakeWatchStream(2)
	first.pushErr(errors.New("boom"))

	second := newFakeWatchStream(2)
	second.pushChanged()

	var mu sync.Mutex
	attempt := 0

	changes := make(chan struct{}, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go watchLoop(ctx, changes, func() (watchStream, error) {
		mu.Lock()
		defer mu.Unlock()
		attempt++
		if attempt == 1 {
			return first, nil
		}
		return second, nil
	})

	select {
	case <-changes:
	case <-time.After(4 * time.Second):
		t.Fatal("expected watchLoop to reconnect and eventually deliver a change")
	}
}
