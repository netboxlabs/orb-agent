package traps

import (
	"container/list"
	"context"
	"log/slog"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/metrics"
)

const (
	receivedName  = "snmp.traps_received"
	droppedName   = "snmp.traps_dropped"
	datagramsName = "snmp.traps_datagrams"
)

// maxSeries bounds the distinct received series the tally holds. A v1 or v2c
// sender able to spoof a registered address can vary the source across a
// registered prefix and the trap name across the closed set, and every
// combination is a map entry that lives until its policy is withdrawn; a /16
// times two hundred names times three versions is tens of millions of them.
// The SDK's cardinality limit folds series only as the callback observes
// them, so it bounds the export and not this map. The cap is the same number,
// so nothing the tally exports is ever folded by the SDK either. Past it, a
// series that does not exist yet is counted under its policy's overflow
// series, device_ip and trap_name both OtherName, and the count survives.
//
// The overflow series need room of their own, or the first of them would be
// the entry past the limit and the SDK would fold an arbitrary series
// instead. So real series stop at seriesLimit, and a reserve below maxSeries
// holds one overflow series per overflowing policy and version. When the
// reserve is used up too, a trap whose policy has no overflow series yet is
// counted as a series_limit drop rather than under a series no policy owns:
// every series in the map carries the policy that can withdraw it. Nothing
// can push the map past maxSeries.
//
// maxSeries is one short of the SDK's limit: the SDK keeps its last slot for
// its own overflow point, so a tally offering exactly the limit would have
// one arbitrary series folded.
const (
	maxSeries       = metrics.CardinalityLimit - 1
	overflowReserve = 100
	seriesLimit     = maxSeries - overflowReserve
)

type receivedKey struct {
	deviceIP, policy, trapName string
	version                    Version
}

// series is one received series' total and whether it is exported. A
// withdrawn policy's series go dormant rather than away: the counter is
// monotonic and the SDK reports a series from the provider's start time, so
// a series that reappeared at one after a policy was deleted and recreated
// under the same name would read as a decrease. A dormant series is not
// observed, keeps its total, resumes from it when its key is counted again,
// and is the first thing evicted when the map is at its cap.
type series struct {
	n    int64
	live bool
}

// Tally holds the counts the receiver produces and exports them through
// observable counters, the way the collector exports gauges. A map the
// package owns is what makes Withdraw possible: a synchronous counter keeps
// every attribute set it ever saw for the life of the process, and a deleted
// policy would keep exporting its devices' trap series after every other
// series of theirs was gone.
type Tally struct {
	logger *slog.Logger

	mu        sync.Mutex
	received  map[receivedKey]*series
	dropped   map[DropReason]int64
	datagrams int64
	// withdrawn is every policy whose lease was released and not acquired
	// again. A count for one of them is kept but stays dormant: a datagram
	// past its registry lookup when the release happened must not bring
	// the policy's series back to life.
	withdrawn map[string]struct{}
	// polSeries counts the received entries and baselines each policy has,
	// its retained state; a withdrawn marker is kept only while this is
	// positive, so the withdrawn set is bounded by retained state rather
	// than by how many policies were ever deleted.
	polSeries map[string]int
	// dormant is the set of series not currently exported, kept beside the
	// map so the overflow path never scans it: with nothing dormant the
	// check is a length, and an eviction is one pop.
	dormant map[receivedKey]struct{}
	// baselines is the total of every series evicted while dormant, keyed
	// like the series and kept in eviction order, so a series that comes
	// back resumes from it and the counter never reads lower. It is bounded
	// at maxBaselines, dropping its oldest, so the tally's memory is bounded
	// at twice the cap.
	baselines     map[receivedKey]*list.Element
	baselineOrder *list.List

	regMu        sync.Mutex
	registration metric.Registration
}

// NewTally returns an empty tally. Register attaches it to the meter.
func NewTally(logger *slog.Logger) *Tally {
	return &Tally{
		logger:        logger,
		received:      make(map[receivedKey]*series),
		dropped:       make(map[DropReason]int64),
		withdrawn:     make(map[string]struct{}),
		polSeries:     make(map[string]int),
		dormant:       make(map[receivedKey]struct{}),
		baselines:     make(map[receivedKey]*list.Element),
		baselineOrder: list.New(),
	}
}

// Received counts one trap for one policy's device. The address set is
// bounded by the policies an operator wrote, since the receiver drops every
// source no policy names before it counts anything, and the series set is
// bounded by maxSeries against a sender who can spoof inside that set.
//
// It reports whether the trap was counted. It is not when the series does
// not exist and there is no room for it, not even for the policy's overflow
// series; the receiver, which counts once per claiming policy, decides from
// the outcomes whether the datagram as a whole is a series_limit drop.
func (t *Tally) Received(deviceIP, policy, trapName string, v Version) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.receivedLocked(deviceIP, policy, trapName, v)
}

// Account runs fn with the tally locked, so everything fn records lands in
// one transaction: a datagram and its outcome are seen together by an
// export, never the datagram alone. The registry's read lock nests inside
// this one when the receiver visits the claims; nothing takes the two in
// the other order.
func (t *Tally) Account(fn func(a *Account)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	fn(&Account{t: t})
}

// Account is the tally as seen from inside one transaction.
type Account struct {
	t *Tally
}

// Datagram counts one datagram in the transaction.
func (a *Account) Datagram() { a.t.datagrams++ }

// Dropped counts one drop in the transaction.
func (a *Account) Dropped(r DropReason) { a.t.dropped[r]++ }

// Received counts one trap in the transaction and reports whether it was
// counted, as Tally.Received does.
func (a *Account) Received(deviceIP, policy, trapName string, v Version) bool {
	return a.t.receivedLocked(deviceIP, policy, trapName, v)
}

func (t *Tally) receivedLocked(deviceIP, policy, trapName string, v Version) bool {
	k := receivedKey{deviceIP, policy, trapName, v}
	if _, exists := t.received[k]; !exists && len(t.received) >= seriesLimit && !t.evictDormant() {
		k = receivedKey{OtherName, policy, OtherName, v}
		if _, exists := t.received[k]; !exists && len(t.received) >= maxSeries && !t.evictDormant() {
			return false
		}
	}
	sr := t.received[k]
	if sr == nil {
		sr = &series{n: t.takeBaseline(k)}
		t.received[k] = sr
		// A brand-new key, not one taken back from a baseline, is a new
		// piece of retained state for its policy. takeBaseline returns a
		// positive total for a real baseline, since a series is at least
		// one before it can be evicted.
		if sr.n == 0 {
			t.polSeries[k.policy]++
		}
	}
	sr.n++
	if _, withdrawn := t.withdrawn[policy]; withdrawn {
		if !sr.live {
			t.dormant[k] = struct{}{}
		}
		return true
	}
	sr.live = true
	delete(t.dormant, k)
	return true
}

// Activate marks a policy acquired, so its counts are exported again. The
// pool calls it as a policy's lease is granted.
func (t *Tally) Activate(policy string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.withdrawn, policy)
}

// evictDormant removes one dormant series to make room for a live one and
// reports whether it found one. A retained total is worth less than a live
// series, so it goes before a live series is folded. The set makes this a
// pop rather than a scan, so a sender past the limit cannot turn every
// datagram into a walk of the map.
func (t *Tally) evictDormant() bool {
	for k := range t.dormant {
		t.keepBaseline(k, t.received[k].n)
		delete(t.dormant, k)
		delete(t.received, k)
		return true
	}
	return false
}

// baseline is one evicted series' total, kept in eviction order.
type baseline struct {
	key receivedKey
	n   int64
}

// maxBaselines bounds the baseline tier at the series limit.
const maxBaselines = maxSeries

// keepBaseline records an evicted series' total, dropping the oldest baseline
// when the tier is full.
func (t *Tally) keepBaseline(k receivedKey, n int64) {
	if el, ok := t.baselines[k]; ok {
		el.Value.(*baseline).n = n
		t.baselineOrder.MoveToFront(el)
		return
	}
	if t.baselineOrder.Len() >= maxBaselines {
		oldest := t.baselineOrder.Back()
		dropped := oldest.Value.(*baseline).key
		delete(t.baselines, dropped)
		t.baselineOrder.Remove(oldest)
		t.releaseSeries(dropped.policy)
	}
	t.baselines[k] = t.baselineOrder.PushFront(&baseline{key: k, n: n})
}

// releaseSeries records that a policy lost one retained entry and prunes its
// withdrawn marker once it has none left, so the marker cannot outlive the
// state it protects.
func (t *Tally) releaseSeries(policy string) {
	t.polSeries[policy]--
	if t.polSeries[policy] <= 0 {
		delete(t.polSeries, policy)
		delete(t.withdrawn, policy)
	}
}

// takeBaseline returns and forgets the baseline for a series, or zero.
func (t *Tally) takeBaseline(k receivedKey) int64 {
	el, ok := t.baselines[k]
	if !ok {
		return 0
	}
	delete(t.baselines, k)
	t.baselineOrder.Remove(el)
	return el.Value.(*baseline).n
}

// Dropped counts one datagram that produced no trap, by reason.
func (t *Tally) Dropped(r DropReason) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dropped[r]++
}

// Datagram counts one datagram. The receiver records it together with the
// datagram's outcome, a drop or a count, so the two sides of the accounting
// agree in every export, including a final one taken while a datagram is in
// flight.
func (t *Tally) Datagram() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.datagrams++
}

// Withdraw makes every received series the policy owns dormant, so a stopped
// policy stops exporting; the totals are kept so a series that reappears
// resumes rather than restarts. Drops and datagrams are process-level and
// are kept.
func (t *Tally) Withdraw(policy string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, sr := range t.received {
		if k.policy == policy {
			sr.live = false
			t.dormant[k] = struct{}{}
		}
	}
	// The marker only protects retained series from an in-flight count
	// reviving them; a policy with none needs none, which is what keeps
	// deleting uniquely named policies from accumulating markers.
	if t.polSeries[policy] > 0 {
		t.withdrawn[policy] = struct{}{}
	}
}

// Register attaches the observable counters. With no meter, which is the case
// whenever no OTLP endpoint is configured, it does nothing, and every count
// still lands in the maps so a later Register would export them.
func (t *Tally) Register() {
	t.regMu.Lock()
	defer t.regMu.Unlock()
	if t.registration != nil {
		return
	}
	m := metrics.GetMeter()
	if m == nil {
		return
	}
	received, err := m.Int64ObservableCounter(receivedName, metric.WithDescription("SNMP traps received, by device, policy, trap name and version"))
	if err != nil {
		t.logger.Error("Failed to create trap counter", "name", receivedName, "error", err)
		return
	}
	dropped, err := m.Int64ObservableCounter(droppedName, metric.WithDescription("SNMP trap datagrams that produced no count, by reason"))
	if err != nil {
		t.logger.Error("Failed to create trap counter", "name", droppedName, "error", err)
		return
	}
	datagrams, err := m.Int64ObservableCounter(datagramsName, metric.WithDescription("SNMP trap datagrams read from the socket before any decision"))
	if err != nil {
		t.logger.Error("Failed to create trap counter", "name", datagramsName, "error", err)
		return
	}
	reg, err := m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		t.mu.Lock()
		defer t.mu.Unlock()
		for k, sr := range t.received {
			if !sr.live {
				continue
			}
			o.ObserveInt64(received, sr.n, metric.WithAttributes(
				attribute.String("device_ip", k.deviceIP),
				attribute.String("policy", k.policy),
				attribute.String("trap_name", k.trapName),
				attribute.String("version", string(k.version)),
			))
		}
		for r, n := range t.dropped {
			o.ObserveInt64(dropped, n, metric.WithAttributes(attribute.String("reason", string(r))))
		}
		o.ObserveInt64(datagrams, t.datagrams)
		return nil
	}, received, dropped, datagrams)
	if err != nil {
		t.logger.Error("Failed to register trap counter callback", "error", err)
		return
	}
	t.registration = reg
}

// Close unregisters the callback. Safe to call without Register.
func (t *Tally) Close() {
	t.regMu.Lock()
	defer t.regMu.Unlock()
	if t.registration == nil {
		return
	}
	if err := t.registration.Unregister(); err != nil {
		t.logger.Warn("Failed to unregister trap counter callback", "error", err)
	}
	t.registration = nil
}

// Test accessors. Exported through _test.go only by convention: they are
// unexported and read under the lock.
// receivedCount is what the series exports: its total while live, zero
// while dormant.
func (t *Tally) receivedCount(deviceIP, policy, trapName string, v Version) int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if sr := t.received[receivedKey{deviceIP, policy, trapName, v}]; sr != nil && sr.live {
		return sr.n
	}
	return 0
}

func (t *Tally) droppedCount(r DropReason) int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.dropped[r]
}

func (t *Tally) baselineCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.baselines)
}

// retainedCount is a series' total whether or not it is exported.
func (t *Tally) retainedCount(deviceIP, policy, trapName string, v Version) int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if sr := t.received[receivedKey{deviceIP, policy, trapName, v}]; sr != nil {
		return sr.n
	}
	return 0
}

func (t *Tally) withdrawnCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.withdrawn)
}

func (t *Tally) dormantCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.dormant)
}

func (t *Tally) seriesCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.received)
}

func (t *Tally) datagramCount() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.datagrams
}
