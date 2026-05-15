package filesmgr

import (
	"log/slog"
	"sync"
)

type subscriber struct {
	id int64
	fn func(FileEvent)
}

type eventBus struct {
	mu          sync.RWMutex
	subscribers []subscriber
	nextID      int64
	logger      *slog.Logger
	closed      bool
}

// newEventBusWithLogger constructs an eventBus with the given logger. If
// logger is nil it falls back to slog.Default().
func newEventBusWithLogger(logger *slog.Logger) *eventBus {
	if logger == nil {
		logger = slog.Default()
	}
	return &eventBus{logger: logger}
}

// subscribe registers fn to receive future events. Returns an unsubscribe
// function the caller may invoke to remove fn from the subscriber set.
//
// If the bus has already been close()d, subscribe still records the
// handler but it will never be invoked (publish is a no-op post-close).
// This is acceptable for the agent-lifetime subscription pattern where
// close happens during Stop and no new subscriptions are made after that
// point. Callers that need to detect a closed bus must do so externally.
func (b *eventBus) subscribe(fn func(FileEvent)) func() {
	b.mu.Lock()
	b.nextID++
	id := b.nextID
	b.subscribers = append(b.subscribers, subscriber{id: id, fn: fn})
	b.mu.Unlock()

	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		for i, s := range b.subscribers {
			if s.id == id {
				b.subscribers = append(b.subscribers[:i], b.subscribers[i+1:]...)
				return
			}
		}
	}
}

// publish invokes every subscriber synchronously. Panics from a subscriber
// are recovered and logged; other subscribers continue. After close() is
// called, publish is a no-op.
func (b *eventBus) publish(ev FileEvent) {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return
	}
	snapshot := make([]subscriber, len(b.subscribers))
	copy(snapshot, b.subscribers)
	b.mu.RUnlock()

	for _, s := range snapshot {
		b.callOne(s, ev)
	}
}

// close empties the subscriber list and marks the bus as closed so that
// subsequent publish() calls are no-ops. Safe to call multiple times.
func (b *eventBus) close() {
	b.mu.Lock()
	b.closed = true
	b.subscribers = nil
	b.mu.Unlock()
}

func (b *eventBus) callOne(s subscriber, ev FileEvent) {
	defer func() {
		if r := recover(); r != nil {
			b.logger.Error("filesmgr subscriber panicked", "panic", r, "event", ev)
		}
	}()
	s.fn(ev)
}
