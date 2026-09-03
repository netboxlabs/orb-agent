package traps

import (
	"fmt"
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

	assert.True(t, w.check(clockID{engineID: "e1"}, 5, 1000), "an unknown engine is learned")
	assert.True(t, w.check(clockID{engineID: "e1"}, 5, 1000), "the same second again is inside the window")
	assert.False(t, w.check(clockID{engineID: "e1"}, 4, 1000), "lower boots is a replay")
	assert.True(t, w.check(clockID{engineID: "e1"}, 5, 1200), "a later time is accepted and moves the clock")

	now = now.Add(200 * time.Second)
	assert.False(t, w.check(clockID{engineID: "e1"}, 5, 1200), "200 seconds later the same time is 200 behind the clock, past the window")
	assert.True(t, w.check(clockID{engineID: "e1"}, 5, 1260), "140 behind the clock is inside the window")
	assert.True(t, w.check(clockID{engineID: "e1"}, 5, 1260), "and did not move the clock back, so it is still inside")
	assert.False(t, w.check(clockID{engineID: "e1"}, 5, 1249), "151 behind is not")

	assert.True(t, w.check(clockID{engineID: "e1"}, 6, 0), "a reboot resets the clock and is accepted")
	assert.False(t, w.check(clockID{engineID: "e1"}, 5, 5000), "the old boots are rejected however far their time claims")
	assert.False(t, w.check(clockID{engineID: "e2"}, maxEngineBoots, 0), "an engine reporting the boots ceiling is never in the window")
	assert.True(t, w.check(clockID{engineID: "e2"}, 1, 1), "a different engine keeps its own clock")
}

// A registered sender holding a v3 credential can authenticate under any
// engine ID it likes, since the key localises against the ID it supplies, so
// the clock map is bounded: past maxEngines the engine seen longest ago is
// evicted to make room, and loses its replay protection until it is seen
// again.
func TestTimeliness_EvictsTheEngineSeenLongestAgo(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	w := newTimeliness(func() time.Time { return now })
	for i := range maxEngines {
		now = now.Add(time.Second)
		assert.True(t, w.check(clockID{engineID: fmt.Sprintf("e%d", i)}, 5, 1000))
	}
	assert.Equal(t, maxEngines, w.size())

	now = now.Add(time.Second)
	assert.True(t, w.check(clockID{engineID: "e0"}, 5, uint32(1000+maxEngines+5)), "seeing e0 again, with its clock advanced, makes it the most recent")
	now = now.Add(time.Second)
	assert.True(t, w.check(clockID{engineID: "new"}, 5, 1000), "a new engine is learned at the cap")
	assert.Equal(t, maxEngines, w.size(), "by evicting one")
	assert.True(t, w.check(clockID{engineID: "e1"}, 4, 1000), "e1 was the one seen longest ago: relearned, so lower boots pass")
	assert.False(t, w.check(clockID{engineID: "e0"}, 4, 1000), "e0 was kept, so lower boots are still a replay")
}

// Eviction is by recency of use, kept in order as engines are touched, so a
// new engine at the cap costs no scan of the map. Refreshing the oldest
// engine moves it to the front; the next new engine evicts the one that
// became oldest.
func TestTimeliness_EvictionOrderFollowsUse(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	w := newTimeliness(func() time.Time { return now })
	for i := range maxEngines {
		assert.True(t, w.check(clockID{engineID: fmt.Sprintf("e%d", i)}, 1, 1))
	}
	assert.True(t, w.check(clockID{engineID: "e0"}, 1, 1), "touch the oldest")
	assert.True(t, w.check(clockID{engineID: "e2"}, 1, 1), "and the third oldest")
	assert.True(t, w.check(clockID{engineID: "new1"}, 1, 1))
	assert.True(t, w.check(clockID{engineID: "new2"}, 1, 1))
	assert.Equal(t, maxEngines, w.size())
	assert.True(t, w.check(clockID{engineID: "e1"}, 0, 1), "e1 was evicted first: relearned, so lower boots pass")
	assert.True(t, w.check(clockID{engineID: "e3"}, 0, 1), "e3 second")
	assert.False(t, w.check(clockID{engineID: "e0"}, 0, 1), "e0 was kept")
	assert.False(t, w.check(clockID{engineID: "e2"}, 0, 1), "e2 was kept")
}

// RFC 3414 bounds engineBoots and engineTime to 2^31 minus 1. gosnmp casts a
// negative wire integer to uint32, so a value past the bound is a malformed
// clock rather than a very late one; it is rejected and, above all, never
// learned, or every genuine value for that clock would read as older.
func TestTimeliness_RejectsOutOfRangeClockValuesWithoutLearningThem(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	w := newTimeliness(func() time.Time { return now })
	id := clockID{engineID: "e1"}
	assert.False(t, w.check(id, 0x80000000, 1), "boots past the bound")
	assert.False(t, w.check(id, 1, 0xffffffff), "time past the bound")
	assert.False(t, w.check(id, 0xffffffff, 0xffffffff))
	assert.Equal(t, 0, w.size(), "nothing was learned from them")
	assert.True(t, w.check(id, 1, 0x7fffffff), "the bound itself is a valid time")
	assert.True(t, w.check(id, 2, 5), "and the clock is a normal one afterwards")
	assert.False(t, w.check(id, 1, 5), "so a lower boots is still a replay")
}
