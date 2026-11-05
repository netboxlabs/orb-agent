package ingest

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/diode-sdk-go/diode/v1/diodepb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type countingClient struct {
	inFlight    int32
	maxInFlight int32

	blockCh   chan struct{}
	releaseCh chan struct{}

	closeCalled atomic.Bool
}

func newCountingClient() *countingClient {
	return &countingClient{}
}

func (c *countingClient) enableBlocking() {
	c.blockCh = make(chan struct{})
	c.releaseCh = make(chan struct{})
}

func (c *countingClient) startBlocking() {
	close(c.blockCh)
}

func (c *countingClient) release() {
	close(c.releaseCh)
}

func (c *countingClient) trackInFlight() func() {
	current := atomic.AddInt32(&c.inFlight, 1)
	for {
		prevMax := atomic.LoadInt32(&c.maxInFlight)
		if current <= prevMax {
			break
		}
		if atomic.CompareAndSwapInt32(&c.maxInFlight, prevMax, current) {
			break
		}
	}
	return func() {
		atomic.AddInt32(&c.inFlight, -1)
	}
}

func (c *countingClient) Ingest(ctx context.Context, _ []diode.Entity, _ ...diode.IngestOption) (*diodepb.IngestResponse, error) {
	done := c.trackInFlight()
	defer done()

	if c.blockCh != nil {
		select {
		case <-c.blockCh:
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		select {
		case <-c.releaseCh:
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		return &diodepb.IngestResponse{}, nil
	}

	time.Sleep(time.Millisecond)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	return &diodepb.IngestResponse{}, nil
}

func (c *countingClient) IngestProto(ctx context.Context, _ []*diodepb.Entity, _ ...diode.IngestOption) (*diodepb.IngestResponse, error) {
	return c.Ingest(ctx, nil)
}

func (c *countingClient) Close() error {
	c.closeCalled.Store(true)
	return nil
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestQueuedClient(inner diode.Client, bufferSize int, callTimeout time.Duration) *QueuedClient {
	c := &QueuedClient{
		inner:       inner,
		logger:      testLogger(),
		requests:    make(chan *ingestRequest, bufferSize),
		callTimeout: callTimeout,
		shutdownCh:  make(chan struct{}),
		done:        make(chan struct{}),
	}
	go c.consumer()
	return c
}

type hangUntilContextClient struct{}

func (h *hangUntilContextClient) Ingest(ctx context.Context, _ []diode.Entity, _ ...diode.IngestOption) (*diodepb.IngestResponse, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (h *hangUntilContextClient) IngestProto(ctx context.Context, _ []*diodepb.Entity, opts ...diode.IngestOption) (*diodepb.IngestResponse, error) {
	return h.Ingest(ctx, nil, opts...)
}

func (h *hangUntilContextClient) Close() error {
	return nil
}

func TestExecuteAppliesDefaultCallTimeout(t *testing.T) {
	inner := &hangUntilContextClient{}
	client := newTestQueuedClient(inner, 1, 50*time.Millisecond)
	t.Cleanup(func() {
		require.NoError(t, client.Close())
	})

	_, err := client.Ingest(context.Background(), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestExecuteRespectsCallerDeadline(t *testing.T) {
	inner := &hangUntilContextClient{}
	client := newTestQueuedClient(inner, 1, time.Minute)
	t.Cleanup(func() {
		require.NoError(t, client.Close())
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := client.Ingest(ctx, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestNewQueuedClientInvalidBufferSize(t *testing.T) {
	inner := newCountingClient()

	client, err := NewQueuedClient(inner, 0, testLogger())
	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "buffer size must be >= 1")
}

func TestSerialExecution(t *testing.T) {
	inner := newCountingClient()
	client, err := NewQueuedClient(inner, 1, testLogger())
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, client.Close())
	})

	const workers = 10
	var wg sync.WaitGroup
	wg.Add(workers)

	for range workers {
		go func() {
			defer wg.Done()
			_, err := client.Ingest(context.Background(), nil)
			assert.NoError(t, err)
		}()
	}

	wg.Wait()
	assert.Equal(t, int32(1), atomic.LoadInt32(&inner.maxInFlight))
}

func TestContextCancelWhileQueued(t *testing.T) {
	inner := newCountingClient()
	inner.enableBlocking()
	inner.startBlocking()

	client, err := NewQueuedClient(inner, 1, testLogger())
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, client.Close())
	})

	firstDone := make(chan struct{})
	go func() {
		_, err := client.Ingest(context.Background(), nil)
		assert.NoError(t, err)
		close(firstDone)
	}()

	require.Eventually(t, func() bool {
		return atomic.LoadInt32(&inner.inFlight) == 1
	}, time.Second, 10*time.Millisecond)

	secondDone := make(chan struct{})
	var secondErr error
	go func() {
		_, secondErr = client.Ingest(context.Background(), nil)
		close(secondDone)
	}()

	require.Eventually(t, func() bool {
		return len(client.(*QueuedClient).requests) == 1
	}, time.Second, 10*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	thirdDone := make(chan struct{})
	var thirdErr error
	go func() {
		_, thirdErr = client.Ingest(ctx, nil)
		close(thirdDone)
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	<-thirdDone
	assert.ErrorIs(t, thirdErr, context.Canceled)

	inner.release()
	<-secondDone
	assert.NoError(t, secondErr)
	<-firstDone
}

func TestCloseRejectsNewIngests(t *testing.T) {
	inner := newCountingClient()
	client, err := NewQueuedClient(inner, 1, testLogger())
	require.NoError(t, err)

	require.NoError(t, client.Close())

	_, err = client.Ingest(context.Background(), nil)
	assert.ErrorIs(t, err, ErrIngestQueueClosed)

	assert.True(t, inner.closeCalled.Load(), "inner client Close should be called")

	_, err = client.Ingest(context.Background(), nil)
	assert.ErrorIs(t, err, ErrIngestQueueClosed)

	require.NoError(t, client.Close(), "Close should be idempotent")
}

func TestCloseConcurrentWithIngest(t *testing.T) {
	inner := newCountingClient()
	client, err := NewQueuedClient(inner, 4, testLogger())
	require.NoError(t, err)

	var wg sync.WaitGroup
	const workers = 50
	wg.Add(workers + 1)

	for range workers {
		go func() {
			defer wg.Done()
			_, _ = client.Ingest(context.Background(), nil)
		}()
	}

	go func() {
		defer wg.Done()
		time.Sleep(time.Millisecond)
		require.NoError(t, client.Close())
	}()

	assert.NotPanics(t, func() {
		wg.Wait()
	})
}

func TestCloseDrainsBufferedPendingRequests(t *testing.T) {
	inner := newCountingClient()
	inner.enableBlocking()
	inner.startBlocking()

	client, err := NewQueuedClient(inner, 4, testLogger())
	require.NoError(t, err)

	go func() {
		_, _ = client.Ingest(context.Background(), nil)
	}()

	require.Eventually(t, func() bool {
		return atomic.LoadInt32(&inner.inFlight) == 1
	}, time.Second, 10*time.Millisecond)

	const pendingCount = 4
	results := make(chan error, pendingCount)
	for range pendingCount {
		go func() {
			_, err := client.Ingest(context.Background(), nil)
			results <- err
		}()
	}

	require.Eventually(t, func() bool {
		return len(client.(*QueuedClient).requests) == pendingCount
	}, time.Second, 10*time.Millisecond)

	closeDone := make(chan struct{})
	go func() {
		require.NoError(t, client.Close())
		close(closeDone)
	}()

	time.Sleep(20 * time.Millisecond)
	inner.release()

	for range pendingCount {
		select {
		case err := <-results:
			assert.ErrorIs(t, err, ErrIngestQueueClosed)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for buffered ingest results after Close")
		}
	}

	<-closeDone
}

func TestCloseDoesNotExecuteBufferedIngests(t *testing.T) {
	inner := newCountingClient()
	inner.enableBlocking()
	inner.startBlocking()

	client, err := NewQueuedClient(inner, 4, testLogger())
	require.NoError(t, err)

	go func() {
		_, _ = client.Ingest(context.Background(), nil)
	}()

	require.Eventually(t, func() bool {
		return atomic.LoadInt32(&inner.inFlight) == 1
	}, time.Second, 10*time.Millisecond)

	const buffered = 2
	for range buffered {
		go func() {
			_, _ = client.Ingest(context.Background(), nil)
		}()
	}

	require.Eventually(t, func() bool {
		return len(client.(*QueuedClient).requests) == buffered
	}, time.Second, 10*time.Millisecond)

	closeDone := make(chan struct{})
	go func() {
		require.NoError(t, client.Close())
		close(closeDone)
	}()

	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, int32(1), atomic.LoadInt32(&inner.maxInFlight))

	inner.release()
	<-closeDone
	assert.Equal(t, int32(1), atomic.LoadInt32(&inner.maxInFlight))
}

func TestCloseDoesNotHangEnqueueDuringShutdownRace(t *testing.T) {
	inner := newCountingClient()
	client, err := NewQueuedClient(inner, 8, testLogger())
	require.NoError(t, err)

	var closeWg sync.WaitGroup
	closeWg.Add(1)
	go func() {
		defer closeWg.Done()
		require.NoError(t, client.Close())
	}()

	const workers = 20
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := client.Ingest(ctx, nil)
			if err != nil {
				assert.True(t,
					errors.Is(err, ErrIngestQueueClosed) || errors.Is(err, context.DeadlineExceeded),
					"unexpected error: %v", err,
				)
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		closeWg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ingest workers hung during concurrent Close")
	}
}

func TestCloseUnblocksBlockedEnqueueWhenBufferFull(t *testing.T) {
	inner := newCountingClient()
	inner.enableBlocking()
	inner.startBlocking()

	client, err := NewQueuedClient(inner, 1, testLogger())
	require.NoError(t, err)

	go func() {
		_, _ = client.Ingest(context.Background(), nil)
	}()

	require.Eventually(t, func() bool {
		return atomic.LoadInt32(&inner.inFlight) == 1
	}, time.Second, 10*time.Millisecond)

	go func() {
		_, _ = client.Ingest(context.Background(), nil)
	}()

	require.Eventually(t, func() bool {
		return len(client.(*QueuedClient).requests) == 1
	}, time.Second, 10*time.Millisecond)

	enqueueDone := make(chan error, 1)
	go func() {
		_, err := client.Ingest(context.Background(), nil)
		enqueueDone <- err
	}()

	time.Sleep(20 * time.Millisecond)

	go func() {
		require.NoError(t, client.Close())
	}()

	select {
	case err := <-enqueueDone:
		assert.ErrorIs(t, err, ErrIngestQueueClosed)
	case <-time.After(time.Second):
		t.Fatal("blocked enqueue did not return after shutdown started")
	}
}

// turnClient holds every ingest until released, and counts the ingests it is
// asked to send.
type turnClient struct {
	release chan struct{}
	sending chan struct{}
	sent    atomic.Int32
}

func (c *turnClient) Ingest(ctx context.Context, _ []diode.Entity, _ ...diode.IngestOption) (*diodepb.IngestResponse, error) {
	c.sent.Add(1)
	c.sending <- struct{}{}
	select {
	case <-c.release:
		return &diodepb.IngestResponse{}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *turnClient) IngestProto(ctx context.Context, _ []*diodepb.Entity, opts ...diode.IngestOption) (*diodepb.IngestResponse, error) {
	return c.Ingest(ctx, nil, opts...)
}

func (c *turnClient) Close() error { return nil }

// A request whose caller stopped waiting while it was queued is not sent when
// its turn comes: the caller has had its answer, and a policy that has stopped
// sends nothing once its stop has returned.
func TestRequestAbandonedWhileQueuedIsNotSent(t *testing.T) {
	inner := &turnClient{release: make(chan struct{}), sending: make(chan struct{}, 4)}
	client, err := NewQueuedClient(inner, 2, testLogger())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	queue := client.(*QueuedClient).requests

	firstDone := make(chan error, 1)
	go func() {
		_, err := client.Ingest(context.Background(), nil)
		firstDone <- err
	}()
	<-inner.sending

	// The caller's context ends with a cause, as a stopped policy's does, and
	// the caller is told that cause.
	stopped := errors.New("run interrupted: policy stopped")
	ctx, cancel := context.WithCancelCause(context.Background())
	abandonedDone := make(chan error, 1)
	go func() {
		_, err := client.Ingest(ctx, nil)
		abandonedDone <- err
	}()
	require.Eventually(t, func() bool { return len(queue) == 1 }, time.Second, 5*time.Millisecond)
	cancel(stopped)
	assert.ErrorIs(t, <-abandonedDone, stopped)

	// Queued behind the abandoned request, so its turn comes first.
	lastDone := make(chan error, 1)
	go func() {
		_, err := client.Ingest(context.Background(), nil)
		lastDone <- err
	}()
	require.Eventually(t, func() bool { return len(queue) == 2 }, time.Second, 5*time.Millisecond)
	close(inner.release)
	require.NoError(t, <-firstDone)
	require.NoError(t, <-lastDone)

	assert.EqualValues(t, 2, inner.sent.Load(), "the first and last requests only")
}

// A caller whose context ends while it waits for room in a full queue is told
// why its context ended.
func TestCallerWaitingForRoomIsToldItsCause(t *testing.T) {
	inner := &turnClient{release: make(chan struct{}), sending: make(chan struct{}, 4)}
	client, err := NewQueuedClient(inner, 1, testLogger())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	queue := client.(*QueuedClient).requests
	defer close(inner.release)

	go func() { _, _ = client.Ingest(context.Background(), nil) }()
	<-inner.sending
	go func() { _, _ = client.Ingest(context.Background(), nil) }()
	require.Eventually(t, func() bool { return len(queue) == 1 }, time.Second, 5*time.Millisecond)

	// The queue is full, so this caller waits for room until its context ends.
	stopped := errors.New("run interrupted: policy stopped")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(stopped)
	_, err = client.Ingest(ctx, nil)
	assert.ErrorIs(t, err, stopped)
}
