package agent

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/netboxlabs/orb-agent/agent/filesmgr"
)

// nameSet is a tiny helper used to model "which file logical names map to
// known backends" inside the subscription bridge.
type nameSet map[string]struct{}

func TestSubscribeToFilesmgr_TriggersRestartOnUpgrade(t *testing.T) {
	restartCh := make(chan string, 1)
	names := nameSet{"worker": {}}

	bridge := func(ev filesmgr.FileEvent) {
		if ev.Type != filesmgr.EventUpgraded {
			return
		}
		if _, ok := names[ev.Entry.Name]; ok {
			restartCh <- ev.Entry.Name
		}
	}

	bridge(filesmgr.FileEvent{
		Type:     filesmgr.EventUpgraded,
		Entry:    filesmgr.FileEntry{Name: "worker"},
		Previous: &filesmgr.FileEntry{Name: "worker"},
	})

	select {
	case got := <-restartCh:
		assert.Equal(t, "worker", got)
	case <-time.After(time.Second):
		t.Fatal("expected restart signal")
	}
}

func TestSubscribeToFilesmgr_IgnoresUnknownBackend(t *testing.T) {
	restartCh := make(chan string, 1)
	names := nameSet{"worker": {}}

	bridge := func(ev filesmgr.FileEvent) {
		if ev.Type != filesmgr.EventUpgraded {
			return
		}
		if _, ok := names[ev.Entry.Name]; ok {
			restartCh <- ev.Entry.Name
		}
	}

	bridge(filesmgr.FileEvent{
		Type:  filesmgr.EventUpgraded,
		Entry: filesmgr.FileEntry{Name: "not-a-backend"},
	})

	select {
	case got := <-restartCh:
		t.Fatalf("unexpected restart for %q", got)
	case <-time.After(50 * time.Millisecond):
		// ok
	}
}
