package traps

import "time"

// timeWindow is RFC 3414's bound on how far behind its engine's clock a
// message may be and still count as timely, in seconds.
const timeWindow = 150

// maxEngineBoots is the boots value an engine reports once its counter is
// exhausted; RFC 3414 says every message carrying it is outside the window.
const maxEngineBoots = 2147483647

// engineClock is what the receiver keeps for one sending engine: the boots
// and time it last learned, and when it learned them, so the engine's current
// time can be estimated without a message.
type engineClock struct {
	boots   uint32
	time    uint32
	learned time.Time
}

// timeliness is the non-authoritative side of RFC 3414 section 3.2.7. A trap's
// sender is the authoritative engine, so the receiver cannot know its clock
// ahead of time; it learns boots and time from the first authenticated message
// and judges every later one against that. A message is outside the window
// when its boots are lower than learned, or equal with a time more than
// timeWindow behind the estimated clock. One ahead of the estimate moves the
// clock forward; one behind it, inside the window, leaves the clock alone, so
// a replayed message can never wind the clock back to admit an older one.
//
// The state is in memory and relearned after a restart, which is what the
// RFC expects of a non-authoritative engine. It is read and written only by
// the receive goroutine, so it needs no lock. Every engine ID here arrived in
// a message that verified against a registered credential, so the map is
// bounded by the devices that hold those credentials.
type timeliness struct {
	clocks map[string]engineClock
	now    func() time.Time
}

func newTimeliness(now func() time.Time) *timeliness {
	return &timeliness{clocks: make(map[string]engineClock), now: now}
}

// check reports whether a message carrying boots and engineTime from engineID
// is inside the window, learning the engine or advancing its clock as it goes.
func (w *timeliness) check(engineID string, boots, engineTime uint32) bool {
	if boots == maxEngineBoots {
		return false
	}
	now := w.now()
	c, known := w.clocks[engineID]
	if !known || boots > c.boots {
		w.clocks[engineID] = engineClock{boots: boots, time: engineTime, learned: now}
		return true
	}
	if boots < c.boots {
		return false
	}
	estimate := int64(c.time) + int64(now.Sub(c.learned)/time.Second)
	if int64(engineTime) < estimate-timeWindow {
		return false
	}
	if int64(engineTime) > estimate {
		w.clocks[engineID] = engineClock{boots: boots, time: engineTime, learned: now}
	}
	return true
}
