package filesmgr

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEventBus_PublishAndSubscribe(t *testing.T) {
	bus := newEventBus()

	var received []FileEvent
	var mu sync.Mutex
	unsubscribe := bus.subscribe(func(ev FileEvent) {
		mu.Lock()
		received = append(received, ev)
		mu.Unlock()
	})
	defer unsubscribe()

	bus.publish(FileEvent{Type: EventInstalled, Entry: FileEntry{Name: "a"}})
	bus.publish(FileEvent{Type: EventUpgraded, Entry: FileEntry{Name: "b"}})

	mu.Lock()
	defer mu.Unlock()
	assert.Len(t, received, 2)
	assert.Equal(t, "a", received[0].Entry.Name)
	assert.Equal(t, EventUpgraded, received[1].Type)
}

func TestEventBus_Unsubscribe(t *testing.T) {
	bus := newEventBus()

	var calls int32
	unsubscribe := bus.subscribe(func(_ FileEvent) {
		atomic.AddInt32(&calls, 1)
	})

	bus.publish(FileEvent{Type: EventInstalled})
	unsubscribe()
	bus.publish(FileEvent{Type: EventInstalled})

	assert.Equal(t, int32(1), atomic.LoadInt32(&calls))
}

func TestEventBus_PanicRecovery(t *testing.T) {
	bus := newEventBus()

	var goodCalls int32
	bus.subscribe(func(_ FileEvent) {
		panic("boom")
	})
	bus.subscribe(func(_ FileEvent) {
		atomic.AddInt32(&goodCalls, 1)
	})

	// Should not panic; the second subscriber must still receive the event.
	bus.publish(FileEvent{Type: EventInstalled})
	assert.Equal(t, int32(1), atomic.LoadInt32(&goodCalls))
}
