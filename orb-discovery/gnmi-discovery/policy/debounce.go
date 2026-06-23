package policy

import "time"

// Debouncer coalesces bursty Trigger() calls into a single fire on C() after a
// quiet window. A single owner goroutine owns the timer; callers only send on
// channels, so there is no concurrent Timer.Reset race. Stop() terminates the
// goroutine.
type Debouncer struct {
	window  time.Duration
	trigger chan struct{}
	fired   chan struct{}
	done    chan struct{}
}

// NewDebouncer returns a started debouncer with the given quiet window.
func NewDebouncer(window time.Duration) *Debouncer {
	d := &Debouncer{
		window:  window,
		trigger: make(chan struct{}, 1),
		fired:   make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	go d.loop()
	return d
}

func (d *Debouncer) loop() {
	timer := time.NewTimer(d.window)
	if !timer.Stop() {
		<-timer.C
	}
	armed := false
	for {
		select {
		case <-d.done:
			timer.Stop()
			return
		case <-d.trigger:
			if !timer.Stop() && armed {
				// drain a possibly-fired timer before resetting
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(d.window)
			armed = true
		case <-timer.C:
			armed = false
			select {
			case d.fired <- struct{}{}:
			default:
			}
		}
	}
}

// Trigger (re)arms the quiet window. Non-blocking.
func (d *Debouncer) Trigger() {
	select {
	case d.trigger <- struct{}{}:
	default:
	}
}

// C is the fire channel.
func (d *Debouncer) C() <-chan struct{} { return d.fired }

// Stop terminates the owner goroutine. Safe to call once.
func (d *Debouncer) Stop() { close(d.done) }
