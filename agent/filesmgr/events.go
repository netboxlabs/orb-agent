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

func newEventBus() *eventBus {
	return &eventBus{logger: slog.Default()}
}

//nolint:unused
func newEventBusWithLogger(logger *slog.Logger) *eventBus {
	return &eventBus{logger: logger}
}

// subscribe registers fn for all future events. The returned function
// removes the subscription.
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
