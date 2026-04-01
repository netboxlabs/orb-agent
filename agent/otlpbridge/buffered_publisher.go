package otlpbridge

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"
)

type publishJob struct {
	topic   string
	payload []byte
}

// BufferedPublisher implements Publisher with a buffered channel that absorbs
// brief MQTT connection outages. A reader goroutine drains the channel,
// waiting for the connection to be ready before each publish.
//
// The underlying ConnectionManager can be swapped via SetConnectionManager
// without losing queued messages — this is how reconnects are handled.
type BufferedPublisher struct {
	mu     sync.RWMutex
	cm     *autopaho.ConnectionManager
	queue  chan publishJob
	ctx    context.Context
	cancel context.CancelFunc
	logger *slog.Logger
	done   chan struct{}
}

// NewBufferedPublisher creates a publisher with a buffered channel of the given
// capacity. The reader goroutine starts immediately; call Close to stop it.
func NewBufferedPublisher(logger *slog.Logger, capacity int) *BufferedPublisher {
	ctx, cancel := context.WithCancel(context.Background())
	bp := &BufferedPublisher{
		queue:  make(chan publishJob, capacity),
		ctx:    ctx,
		cancel: cancel,
		logger: logger,
		done:   make(chan struct{}),
	}
	go bp.run()
	return bp
}

// SetConnectionManager swaps the underlying autopaho connection manager.
// Called from the OnReadyHook on each (re)connect.
func (bp *BufferedPublisher) SetConnectionManager(cm *autopaho.ConnectionManager) {
	bp.mu.Lock()
	bp.cm = cm
	bp.mu.Unlock()
}

// Publish enqueues the message for async delivery. Returns an error only if
// the buffer is full or the publisher has been closed.
func (bp *BufferedPublisher) Publish(_ context.Context, topic string, payload []byte) error {
	select {
	case <-bp.ctx.Done():
		return fmt.Errorf("publisher closed")
	case bp.queue <- publishJob{topic: topic, payload: payload}:
		return nil
	default:
		return fmt.Errorf("OTLP publish buffer full (capacity %d)", cap(bp.queue))
	}
}

// Close stops the reader goroutine and waits for it to exit.
// Messages still in the queue are abandoned.
func (bp *BufferedPublisher) Close() {
	bp.cancel()
	<-bp.done
}

func (bp *BufferedPublisher) run() {
	defer close(bp.done)
	for {
		select {
		case <-bp.ctx.Done():
			return
		case job := <-bp.queue:
			bp.publish(job)
		}
	}
}

func (bp *BufferedPublisher) publish(job publishJob) {
	bp.mu.RLock()
	cm := bp.cm
	bp.mu.RUnlock()

	if cm == nil {
		bp.logger.Warn("OTLP publish dropped, no connection manager", "topic", job.topic)
		return
	}

	// Wait for the connection to be ready (handles brief outages).
	waitCtx, waitCancel := context.WithTimeout(bp.ctx, 30*time.Second)
	err := cm.AwaitConnection(waitCtx)
	waitCancel()
	if err != nil {
		bp.logger.Warn("OTLP publish dropped, connection not ready",
			"topic", job.topic, "error", err)
		return
	}

	if _, err := cm.Publish(bp.ctx, &paho.Publish{
		Topic:   job.topic,
		Payload: job.payload,
		QoS:     0,
		Retain:  false,
	}); err != nil {
		bp.logger.Error("buffered OTLP publish failed",
			"topic", job.topic, "error", err)
	}
}
