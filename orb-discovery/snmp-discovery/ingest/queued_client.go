package ingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/diode-sdk-go/diode/v1/diodepb"
)

// defaultIngestCallTimeout is applied when callers pass a context with no deadline.
// Derived from Grafana production diode-ingester Ingest latency
// (rpc_server_duration_milliseconds, 7d): p50 ~5ms, mean ~190ms, p99 ~938ms,
// max histogram bucket 10s. Set to 3× the max bucket so hung calls fail instead
// of blocking the single consumer indefinitely.
const defaultIngestCallTimeout = 30 * time.Second

// ErrIngestQueueClosed is returned when an ingest request cannot be enqueued
// because the queued client is shutting down or has been closed.
var ErrIngestQueueClosed = errors.New("ingest queue closed")

type ingestResult struct {
	resp *diodepb.IngestResponse
	err  error
}

type ingestRequest struct {
	ctx    context.Context
	run    func(context.Context) (*diodepb.IngestResponse, error)
	result chan ingestResult
}

// QueuedClient serializes ingest calls to an inner diode.Client through a
// buffered channel consumed by a single goroutine.
type QueuedClient struct {
	inner       diode.Client
	logger      *slog.Logger
	requests    chan *ingestRequest
	callTimeout time.Duration
	// shutdownCh is closed (never written to) to broadcast shutdown to all waiters.
	shutdownCh chan struct{}
	closeOnce  sync.Once
	// done is closed by the consumer goroutine when it exits; Close waits on it.
	done chan struct{}
}

// NewQueuedClient wraps inner with a buffered queue and single consumer goroutine.
func NewQueuedClient(inner diode.Client, bufferSize int, logger *slog.Logger) (diode.Client, error) {
	if bufferSize < 1 {
		return nil, fmt.Errorf("ingest queue buffer size must be >= 1, got %d", bufferSize)
	}

	c := &QueuedClient{
		inner:       inner,
		logger:      logger,
		requests:    make(chan *ingestRequest, bufferSize),
		callTimeout: defaultIngestCallTimeout,
		shutdownCh:  make(chan struct{}),
		done:        make(chan struct{}),
	}
	go c.consumer()
	return c, nil
}

func (c *QueuedClient) consumer() {
	defer close(c.done)

	for {
		// Non-blocking check: Close may have run during execute() on the prior
		// iteration. The select below handles shutdown while blocked for work.
		if c.shutdownSignaled() {
			c.drainPendingFailures()
			return
		}

		select {
		case req := <-c.requests:
			// Re-check after dequeue: shutdown may have started while the request
			// sat in the buffer; fail it instead of executing after Close.
			if c.shutdownSignaled() {
				c.deliverFailure(req)
				c.drainPendingFailures()
				return
			}
			c.execute(req)
		case <-c.shutdownCh:
			c.drainPendingFailures()
			return
		}
	}
}

// shutdownSignaled reports whether Close has started without blocking. Enqueue
// and the consumer use this for fast-path checks; blocking waits still select
// on shutdownCh directly so they wake as soon as Close closes the channel.
func (c *QueuedClient) shutdownSignaled() bool {
	select {
	case <-c.shutdownCh:
		return true
	default:
		return false
	}
}

func (c *QueuedClient) execute(req *ingestRequest) {
	ctx := req.ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.callTimeout)
		defer cancel()
	}

	resp, err := req.run(ctx)
	select {
	case req.result <- ingestResult{resp: resp, err: err}:
	default:
		c.logger.Warn("ingest result not delivered: caller no longer waiting")
	}
}

func (c *QueuedClient) enqueue(
	ctx context.Context,
	run func(context.Context) (*diodepb.IngestResponse, error),
) (*diodepb.IngestResponse, error) {
	req := &ingestRequest{
		ctx:    ctx,
		run:    run,
		result: make(chan ingestResult, 1),
	}

	// Fast-path reject when shutdown already started; the select below handles
	// the race where Close runs while we wait for queue space.
	if c.shutdownSignaled() {
		return nil, ErrIngestQueueClosed
	}

	select {
	case c.requests <- req:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.shutdownCh:
		return nil, ErrIngestQueueClosed
	}

	select {
	case res := <-req.result:
		return res.resp, res.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		select {
		case res := <-req.result:
			return res.resp, res.err
		default:
			return nil, ErrIngestQueueClosed
		}
	}
}

func (c *QueuedClient) deliverFailure(req *ingestRequest) {
	select {
	case req.result <- ingestResult{err: ErrIngestQueueClosed}:
	default:
		c.logger.Warn("ingest queue closed result not delivered: caller no longer waiting")
	}
}

func (c *QueuedClient) drainPendingFailures() {
	for {
		select {
		case req := <-c.requests:
			c.deliverFailure(req)
		default:
			return
		}
	}
}

// Ingest enqueues an ingest request and blocks until it completes or ctx is cancelled.
func (c *QueuedClient) Ingest(
	ctx context.Context,
	entities []diode.Entity,
	opts ...diode.IngestOption,
) (*diodepb.IngestResponse, error) {
	return c.enqueue(ctx, func(callCtx context.Context) (*diodepb.IngestResponse, error) {
		return c.inner.Ingest(callCtx, entities, opts...)
	})
}

// IngestProto enqueues a proto ingest request and blocks until it completes or ctx is cancelled.
func (c *QueuedClient) IngestProto(
	ctx context.Context,
	entities []*diodepb.Entity,
	opts ...diode.IngestOption,
) (*diodepb.IngestResponse, error) {
	return c.enqueue(ctx, func(callCtx context.Context) (*diodepb.IngestResponse, error) {
		return c.inner.IngestProto(callCtx, entities, opts...)
	})
}

// Close stops accepting new work, fails buffered requests that have not started,
// waits for any in-flight ingest and the consumer to exit, then closes the inner
// client. Close is idempotent.
func (c *QueuedClient) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.shutdownCh)
		<-c.done
		err = c.inner.Close()
	})
	return err
}
