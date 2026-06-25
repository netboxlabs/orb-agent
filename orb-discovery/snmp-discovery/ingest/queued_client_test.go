package ingest

import (
	"context"
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
