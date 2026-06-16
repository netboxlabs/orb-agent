package gnmi

import (
	"context"
	"errors"
	"time"
)

// FakeSession is an in-memory Session for tests. It replays scripted
// notifications and answers Capabilities/Get from fixed data.
type FakeSession struct {
	Caps            *CapabilitiesResult
	CapsErr         error
	OnChangeStream  []Notification // replayed once for Subscribe(OnChange)
	OnChangeSupport bool
	SampleSnapshots []Notification // re-sent every SampleReplay for Subscribe(Sample)
	SampleReplay    time.Duration  // gap between SAMPLE re-sends (default 20ms)
	StreamErr       error          // if set, sent on the error channel after replay (simulates a mid-stream drop)
	GetResult       Notification
	GetErr          error
	ConfigBytes     []byte // returned by GetConfig
	ConfigErr       error  // if set, GetConfig returns this error
	ConfigGets      int    // count of GetConfig calls (test assertion)
	Closed          bool
	StopSubscribes  int // count of StopSubscribe calls (test assertion)
}

// Capabilities returns the scripted capabilities.
func (f *FakeSession) Capabilities(_ context.Context) (*CapabilitiesResult, error) {
	return f.Caps, f.CapsErr
}

// Subscribe replays the scripted stream. OnChange replays once then errors (if
// StreamErr set) or blocks; SAMPLE re-sends the snapshot set every SampleReplay,
// matching real SAMPLE semantics so periodic reconciliation/pruning is exercised.
func (f *FakeSession) Subscribe(ctx context.Context, mode Mode, _ []string, _ int) (<-chan Notification, <-chan error, error) {
	if mode == OnChange && !f.OnChangeSupport {
		return nil, nil, errors.New("on_change unsupported")
	}
	notes := make(chan Notification)
	errs := make(chan error, 1)
	send := func(stream []Notification) bool { // false if ctx cancelled mid-send
		for _, n := range stream {
			select {
			case notes <- n:
			case <-ctx.Done():
				return false
			}
		}
		return true
	}
	go func() {
		defer close(notes)
		defer close(errs)
		if mode == Sample {
			interval := f.SampleReplay
			if interval <= 0 {
				interval = 20 * time.Millisecond
			}
			for {
				if !send(f.SampleSnapshots) {
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(interval):
				}
			}
		}
		if !send(f.OnChangeStream) {
			return
		}
		if f.StreamErr != nil {
			select {
			case errs <- f.StreamErr:
			case <-ctx.Done():
			}
			return
		}
		<-ctx.Done()
	}()
	return notes, errs, nil
}

// GetOnce returns the scripted Get result.
func (f *FakeSession) GetOnce(_ context.Context, _ []string) (Notification, error) {
	return f.GetResult, f.GetErr
}

// GetConfig records the call and returns the scripted config bytes/error.
func (f *FakeSession) GetConfig(_ context.Context) ([]byte, error) {
	f.ConfigGets++
	return f.ConfigBytes, f.ConfigErr
}

// StopSubscribe records the call; the fake has no real subscription to tear down.
func (f *FakeSession) StopSubscribe() { f.StopSubscribes++ }

// Close marks the session closed.
func (f *FakeSession) Close() error { f.Closed = true; return nil }

// FakeDialer always returns the same FakeSession.
type FakeDialer struct{ Session *FakeSession }

// Dial returns the configured fake session.
func (d *FakeDialer) Dial(_ context.Context, _ TargetSpec) (Session, error) {
	return d.Session, nil
}
