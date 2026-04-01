package otlpbridge

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBufferedPublisher_EnqueuesWithoutBlocking(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	bp := NewBufferedPublisher(logger, 10)
	defer bp.Close()

	// Without a CM set, messages will be dequeued and dropped by the reader,
	// but Publish itself should return nil (enqueued successfully).
	for i := 0; i < 10; i++ {
		err := bp.Publish(context.Background(), "test/topic", []byte("payload"))
		assert.NoError(t, err, "enqueue %d should succeed", i)
	}
}

func TestBufferedPublisher_ReturnsErrorWhenFull(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	// Create with capacity 2 but don't start the reader — queue won't drain.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bp := &BufferedPublisher{
		queue:  make(chan publishJob, 2),
		logger: logger,
		done:   make(chan struct{}),
		ctx:    ctx,
		cancel: cancel,
	}

	// Fill the buffer
	require.NoError(t, bp.Publish(context.Background(), "t", []byte("1")))
	require.NoError(t, bp.Publish(context.Background(), "t", []byte("2")))

	// Third should fail — buffer is full and no reader is draining
	err := bp.Publish(context.Background(), "t", []byte("3"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "buffer full")
}

func TestBufferedPublisher_DropsWhenNoCM(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	bp := NewBufferedPublisher(logger, 10)
	defer bp.Close()

	// Publish without setting a CM — message should be dropped (not block forever)
	err := bp.Publish(context.Background(), "test/topic", []byte("payload"))
	require.NoError(t, err)

	// Give the reader time to process
	time.Sleep(50 * time.Millisecond)

	// Queue should be empty (message was consumed and dropped)
	assert.Equal(t, 0, len(bp.queue))
}

func TestBufferedPublisher_CloseStopsReader(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	bp := NewBufferedPublisher(logger, 10)

	// Enqueue some messages
	for i := 0; i < 5; i++ {
		_ = bp.Publish(context.Background(), "test/topic", []byte("payload"))
	}

	// Close should return without hanging
	done := make(chan struct{})
	go func() {
		bp.Close()
		close(done)
	}()

	select {
	case <-done:
		// expected
	case <-time.After(2 * time.Second):
		t.Fatal("Close() should not hang")
	}
}

func TestBufferedPublisher_PublishAfterCloseReturnsError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	bp := NewBufferedPublisher(logger, 10)
	bp.Close()

	err := bp.Publish(context.Background(), "test/topic", []byte("payload"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestBufferedPublisher_SetConnectionManager(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	bp := NewBufferedPublisher(logger, 10)
	defer bp.Close()

	bp.mu.RLock()
	assert.Nil(t, bp.cm)
	bp.mu.RUnlock()

	// Verify the setter doesn't panic with nil
	bp.SetConnectionManager(nil)
	bp.mu.RLock()
	assert.Nil(t, bp.cm)
	bp.mu.RUnlock()
}

func TestBufferedPublisher_ImplementsPublisher(t *testing.T) {
	// Compile-time check
	var _ Publisher = (*BufferedPublisher)(nil)
}
