package policy

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDebouncerFiresAfterQuiet(t *testing.T) {
	d := NewDebouncer(50 * time.Millisecond)
	defer d.Stop()
	d.Trigger()
	select {
	case <-d.C():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("debouncer did not fire")
	}
}

func TestDebouncerCollapsesBurst(t *testing.T) {
	d := NewDebouncer(80 * time.Millisecond)
	defer d.Stop()
	for i := 0; i < 5; i++ {
		d.Trigger()
		time.Sleep(20 * time.Millisecond) // each within the window -> resets
	}
	start := time.Now()
	<-d.C()
	// fired only after the last trigger + window, i.e. one fire, not five
	require.GreaterOrEqual(t, time.Since(start), 40*time.Millisecond)
}

func TestDebouncerStopEndsGoroutine(t *testing.T) {
	before := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		d := NewDebouncer(10 * time.Millisecond)
		d.Trigger()
		d.Stop()
	}
	time.Sleep(50 * time.Millisecond)
	after := runtime.NumGoroutine()
	// allow a little slack for the scheduler, but 20 leaked goroutines would fail
	require.LessOrEqual(t, after, before+2)
}
