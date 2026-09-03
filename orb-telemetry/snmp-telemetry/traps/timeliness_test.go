package traps

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// RFC 3414 section 3.2.7(b), the non-authoritative side: the receiver learns
// each engine's boots and time from the first authenticated message, then
// treats a message as outside the window when its boots are lower than
// learned or its time is more than 150 seconds behind the clock the receiver
// keeps for that engine. A message ahead of that clock moves it forward; one
// behind it, inside the window, leaves it alone, so a replay cannot wind the
// clock back.
func TestTimeliness_LearnsThenRejectsLowerBootsAndStaleTime(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	w := newTimeliness(func() time.Time { return now })

	assert.True(t, w.check("e1", 5, 1000), "an unknown engine is learned")
	assert.True(t, w.check("e1", 5, 1000), "the same second again is inside the window")
	assert.False(t, w.check("e1", 4, 1000), "lower boots is a replay")
	assert.True(t, w.check("e1", 5, 1200), "a later time is accepted and moves the clock")

	now = now.Add(200 * time.Second)
	assert.False(t, w.check("e1", 5, 1200), "200 seconds later the same time is 200 behind the clock, past the window")
	assert.True(t, w.check("e1", 5, 1260), "140 behind the clock is inside the window")
	assert.True(t, w.check("e1", 5, 1260), "and did not move the clock back, so it is still inside")
	assert.False(t, w.check("e1", 5, 1249), "151 behind is not")

	assert.True(t, w.check("e1", 6, 0), "a reboot resets the clock and is accepted")
	assert.False(t, w.check("e1", 5, 5000), "the old boots are rejected however far their time claims")
	assert.False(t, w.check("e2", maxEngineBoots, 0), "an engine reporting the boots ceiling is never in the window")
	assert.True(t, w.check("e2", 1, 1), "a different engine keeps its own clock")
}
