package traps

import (
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
// instead. So real series stop at seriesLimit, a reserve below maxSeries
// holds one overflow series per overflowing policy and version, and the last
// versionCount slots of the reserve are kept for one process-wide overflow
// series per version, where a policy whose own overflow series would not fit
// is counted. Nothing can push the map past maxSeries.
const (
	maxSeries       = metrics.CardinalityLimit
	overflowReserve = 100
	seriesLimit     = maxSeries - overflowReserve
	// versionCount is how many Version values exist: V1, V2c and V3.
	versionCount = 3
)

type receivedKey struct {
	deviceIP, policy, trapName string
	version                    Version
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
	received  map[receivedKey]int64
	dropped   map[DropReason]int64
	datagrams int64

	regMu        sync.Mutex
	registration metric.Registration
}

// NewTally returns an empty tally. Register attaches it to the meter.
func NewTally(logger *slog.Logger) *Tally {
	return &Tally{
		logger:   logger,
		received: make(map[receivedKey]int64),
		dropped:  make(map[DropReason]int64),
	}
}

// Received counts one trap for one policy's device. The address set is
// bounded by the policies an operator wrote, since the receiver drops every
// source no policy names before it counts anything, and the series set is
// bounded by maxSeries against a sender who can spoof inside that set.
func (t *Tally) Received(deviceIP, policy, trapName string, v Version) {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := receivedKey{deviceIP, policy, trapName, v}
	if _, exists := t.received[k]; !exists && len(t.received) >= seriesLimit {
		k = receivedKey{OtherName, policy, OtherName, v}
		if _, exists := t.received[k]; !exists && len(t.received) >= maxSeries-versionCount {
			k = receivedKey{OtherName, OtherName, OtherName, v}
		}
	}
	t.received[k]++
}

// Dropped counts one datagram that produced no trap, by reason.
func (t *Tally) Dropped(r DropReason) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dropped[r]++
}

// Datagram counts one datagram read from the socket, before any decision, so
// the gap against received plus dropped is the loss an operator cannot
// otherwise see.
func (t *Tally) Datagram() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.datagrams++
}

// Withdraw drops every received series the policy owns, so a stopped policy
// stops exporting. Drops and datagrams are process-level and are kept.
func (t *Tally) Withdraw(policy string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k := range t.received {
		if k.policy == policy {
			delete(t.received, k)
		}
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
		for k, n := range t.received {
			o.ObserveInt64(received, n, metric.WithAttributes(
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
func (t *Tally) receivedCount(deviceIP, policy, trapName string, v Version) int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.received[receivedKey{deviceIP, policy, trapName, v}]
}

func (t *Tally) droppedCount(r DropReason) int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.dropped[r]
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
