package ingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/diode-sdk-go/diode/v1/diodepb"
)

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
	inner      diode.Client
	logger     *slog.Logger
	requests   chan *ingestRequest
	shutdownCh chan struct{}
	closeOnce  sync.Once
	done       chan struct{}
}

// NewQueuedClient wraps inner with a buffered queue and single consumer goroutine.
func NewQueuedClient(inner diode.Client, bufferSize int, logger *slog.Logger) (diode.Client, error) {
	if bufferSize < 1 {
		return nil, fmt.Errorf("ingest queue buffer size must be >= 1, got %d", bufferSize)
	}

	c := &QueuedClient{
		inner:      inner,
		logger:     logger,
		requests:   make(chan *ingestRequest, bufferSize),
		shutdownCh: make(chan struct{}),
		done:       make(chan struct{}),
	}
	go c.consumer()
	return c, nil
}

func (c *QueuedClient) consumer() {
	defer close(c.done)

	for {
		if c.shutdownSignaled() {
			c.drainPendingFailures()
			return
		}

		select {
		case req := <-c.requests:
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

func (c *QueuedClient) shutdownSignaled() bool {
	select {
	case <-c.shutdownCh:
		return true
	default:
		return false
	}
}

func (c *QueuedClient) execute(req *ingestRequest) {
	resp, err := req.run(req.ctx)
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
