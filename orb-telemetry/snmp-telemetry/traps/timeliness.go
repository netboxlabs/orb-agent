package traps

import (
	"container/list"
	"net/netip"
	"time"

	"github.com/gosnmp/gosnmp"
)

// clockID names the clock a v3 message is judged by: the sender's address,
// the credential that verified it, identified by everything a registered
// user is compared on, and the engine ID it carries. It is a struct rather
// than a joined string so no operator-chosen value can act as a field
// boundary and make two principals one clock.
type clockID struct {
	src       netip.Addr
	user      string
	authPass  string
	privPass  string
	authProto gosnmp.SnmpV3AuthProtocol
	privProto gosnmp.SnmpV3PrivProtocol
	engineID  string
}

// principal is the clockID without its engine ID: one sender with one
// credential, which is what can churn engine IDs and what must not be able
// to evict anyone else's clock by doing so.
func (id clockID) principal() clockID {
	id.engineID = ""
	return id
}

// credential is the clockID without its sender or engine ID: the level above
// the principal, since a holder of one credential can spoof every registered
// source it covers and so mint principals at will. Eviction at the global
// bound stays inside the credential's own group whenever it holds a clock.
func (id clockID) credential() clockID {
	id.src = netip.Addr{}
	id.engineID = ""
	return id
}

// maxEnginesPerPrincipal bounds the clocks one principal may hold. A device
// has one engine ID, two across a re-provisioning; past the bound the
// principal's own least recently used clock goes, so a principal cycling
// through engine IDs evicts only itself and never reaches the global bound
// on anyone else's behalf.
const maxEnginesPerPrincipal = 8

// timeWindow is RFC 3414's bound on how far behind its engine's clock a
// message may be and still count as timely, in seconds.
const timeWindow = 150

// maxEngineBoots is the boots value an engine reports once its counter is
// exhausted; RFC 3414 says every message carrying it is outside the window.
// It is also the largest value either clock field may hold: gosnmp casts a
// negative wire integer to uint32, so a value past it is a malformed clock
// and is rejected before it can be learned.
const maxEngineBoots = 2147483647

// maxEngines bounds the clock map. A registered sender holding a v3
// credential can authenticate under any engine ID it chooses, since the key
// localises against the ID the message supplies, so the map cannot be left
// to grow with the IDs seen. Past the bound the engine used longest ago is
// evicted, and loses its replay protection until it is seen again; ten
// thousand is far more engines than the addresses a socket's policies name.
// The order is kept as engines are used, so an eviction costs no scan: a
// credential holder churning engine IDs pays the receive goroutine nothing
// beyond the localisation it already paid for.
const maxEngines = 10000

// engineClock is what the receiver keeps for one sending engine: the boots
// and time it last learned, and when it learned them, so the engine's current
// time can be estimated without a message.
type engineClock struct {
	id      clockID
	boots   uint32
	time    uint32
	learned time.Time
	// global, local and group are this clock's places in the global recency
	// list, in its principal's own, and in its credential's.
	global *list.Element
	local  *list.Element
	group  *list.Element
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
// the receive goroutine, so it needs no lock. Every engine here arrived in a
// message that verified against a registered credential, keyed by the
// receiver with the sender's address, so a device can poison only its own.
type timeliness struct {
	clocks map[clockID]*list.Element
	// order holds the engines most recently used first; the back is the
	// next to be evicted at the global bound.
	order *list.List
	// perPrincipal holds each principal's clocks most recently used first;
	// the back is the next to be evicted at the principal's bound.
	perPrincipal map[clockID]*list.List
	// perCredential holds each credential's clocks most recently used
	// first, across every source it is used from; the back is the next to
	// be evicted at the global bound when the credential holds any.
	perCredential map[clockID]*list.List
	now           func() time.Time
}

func newTimeliness(now func() time.Time) *timeliness {
	return &timeliness{
		clocks:        make(map[clockID]*list.Element),
		order:         list.New(),
		perPrincipal:  make(map[clockID]*list.List),
		perCredential: make(map[clockID]*list.List),
		now:           now,
	}
}

// listFor returns the recency list under key in m, creating it.
func listFor(m map[clockID]*list.List, key clockID) *list.List {
	l := m[key]
	if l == nil {
		l = list.New()
		m[key] = l
	}
	return l
}

// evict removes one clock from every structure that holds it.
func (w *timeliness) evict(el *list.Element) {
	c := el.Value.(*engineClock)
	delete(w.clocks, c.id)
	w.order.Remove(el)
	p := c.id.principal()
	if l := w.perPrincipal[p]; l != nil {
		l.Remove(c.local)
		if l.Len() == 0 {
			delete(w.perPrincipal, p)
		}
	}
	g := c.id.credential()
	if l := w.perCredential[g]; l != nil {
		l.Remove(c.group)
		if l.Len() == 0 {
			delete(w.perCredential, g)
		}
	}
}

// check reports whether a message carrying boots and engineTime from the
// clock named by id is inside the window, learning the clock or advancing it
// as it goes.
func (w *timeliness) check(id clockID, boots, engineTime uint32) bool {
	if boots >= maxEngineBoots || engineTime > maxEngineBoots {
		return false
	}
	now := w.now()
	el, known := w.clocks[id]
	if !known {
		p, g := id.principal(), id.credential()
		mine := listFor(w.perPrincipal, p)
		ours := listFor(w.perCredential, g)
		// The churner's own clocks go first. A principal past its bound
		// evicts its own; at the global bound a principal holding any clock
		// evicts its own, a credential holding any clock evicts within its
		// own group, and only a credential's very first clock displaces the
		// globally oldest, once. So neither engine-ID churn nor source churn
		// under one credential reaches another credential's replay state.
		switch {
		case mine.Len() >= maxEnginesPerPrincipal || (w.order.Len() >= maxEngines && mine.Len() > 0):
			w.evict(mine.Back().Value.(*engineClock).global)
		case w.order.Len() >= maxEngines && ours.Len() > 0:
			w.evict(ours.Back().Value.(*engineClock).global)
		case w.order.Len() >= maxEngines:
			w.evict(w.order.Back())
		}
		// An eviction that emptied a list removed it from its map; the new
		// clock must join the lists the maps hold, or the next clock would
		// find none and evict globally.
		mine = listFor(w.perPrincipal, p)
		ours = listFor(w.perCredential, g)
		c := &engineClock{id: id, boots: boots, time: engineTime, learned: now}
		c.global = w.order.PushFront(c)
		c.local = mine.PushFront(c)
		c.group = ours.PushFront(c)
		w.clocks[id] = c.global
		return true
	}
	c := el.Value.(*engineClock)
	if boots > c.boots {
		c.boots, c.time, c.learned = boots, engineTime, now
		w.touch(c)
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
		c.time, c.learned = engineTime, now
	}
	w.touch(c)
	return true
}

// touch marks a clock as just used in both recency lists.
func (w *timeliness) touch(c *engineClock) {
	w.order.MoveToFront(c.global)
	if l := w.perPrincipal[c.id.principal()]; l != nil {
		l.MoveToFront(c.local)
	}
	if l := w.perCredential[c.id.credential()]; l != nil {
		l.MoveToFront(c.group)
	}
}

// Test accessors: the map's size, and the global list's length, which must
// stay equal or a clock has leaked out of one and not the other.
func (w *timeliness) size() int     { return len(w.clocks) }
func (w *timeliness) orderLen() int { return w.order.Len() }
