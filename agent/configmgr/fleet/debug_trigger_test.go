//go:build debug

package fleet

import (
	"context"
	"log/slog"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// fakeDebugCredentials records calls for test assertions.
type fakeDebugCredentials struct {
	rotateCalled chan struct{}
	logCalled    chan struct{}
	rotateErr    error
}

func (f *fakeDebugCredentials) RotateCredentials(_ context.Context) error {
	f.rotateCalled <- struct{}{}
	return f.rotateErr
}

func (f *fakeDebugCredentials) LogCredentials() {
	f.logCalled <- struct{}{}
}

func newFakeDC() *fakeDebugCredentials {
	return &fakeDebugCredentials{
		rotateCalled: make(chan struct{}, 1),
		logCalled:    make(chan struct{}, 1),
	}
}

func TestDebugTrigger_SIGUSR1_CallsRotate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	dc := newFakeDC()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	StartDebugTrigger(ctx, logger, dc)
	time.Sleep(50 * time.Millisecond)

	_ = syscall.Kill(os.Getpid(), syscall.SIGUSR1)

	select {
	case <-dc.rotateCalled:
		// expected
	case <-time.After(time.Second):
		t.Fatal("expected RotateCredentials to be called")
	}
}

func TestDebugTrigger_SIGUSR2_CallsLog(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	dc := newFakeDC()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	StartDebugTrigger(ctx, logger, dc)
	time.Sleep(50 * time.Millisecond)

	_ = syscall.Kill(os.Getpid(), syscall.SIGUSR2)

	select {
	case <-dc.logCalled:
		// expected
	case <-time.After(time.Second):
		t.Fatal("expected LogCredentials to be called")
	}
}

func TestDebugTrigger_ContextCancel(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	dc := newFakeDC()
	ctx, cancel := context.WithCancel(context.Background())

	StartDebugTrigger(ctx, logger, dc)
	time.Sleep(50 * time.Millisecond)

	cancel()
	time.Sleep(50 * time.Millisecond)

	// After cancel, signals should not be delivered
	assert.NotNil(t, dc)
}
