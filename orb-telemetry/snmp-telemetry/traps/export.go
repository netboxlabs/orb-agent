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

// maxUnknownSources bounds the distinct device_ip values the tally will hold
// for sources no policy names. With --trap-accept-unknown on, every distinct
// address that sends a datagram makes a new series, and a source address is
// spoofable, so without a cap the map grows from the network without bound.
// A thousand is far more unregistered senders than an operator closing a
// registration gap needs to see, and a tenth of the SDK cardinality ceiling
// this backend sets, so the fold happens here where the count survives it
// rather than in the SDK where the metric stops answering anything.
const maxUnknownSources = 1000

// unknownSourceOverflow is the device_ip every unknown source past the cap is
// counted under, mirroring the closed sink NameFor folds unrecognised trap
// OIDs into: the traps are still counted, they just stop naming their sender.
const unknownSourceOverflow = "other"

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
	// unknownSources is the set of addresses that have already been given a
	// device_ip of their own with no policy behind them, so the cap counts
	// distinct senders rather than datagrams.
	unknownSources map[string]struct{}

	regMu        sync.Mutex
	registration metric.Registration
}

// NewTally returns an empty tally. Register attaches it to the meter.
func NewTally(logger *slog.Logger) *Tally {
	return &Tally{
		logger:         logger,
		received:       make(map[receivedKey]int64),
		dropped:        make(map[DropReason]int64),
		unknownSources: make(map[string]struct{}),
	}
}

// Received counts one trap for one policy's device.
//
// A claim with no policy came from an address no policy names, which only
// --trap-accept-unknown produces. Those addresses are the ones a stranger
// chooses, so they are capped: past maxUnknownSources distinct ones the count
// still lands, under the overflow device_ip. A registered device is bounded by
// the policies an operator wrote and is never folded.
func (t *Tally) Received(deviceIP, policy, trapName string, v Version) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if policy == "" {
		if _, seen := t.unknownSources[deviceIP]; !seen {
			if len(t.unknownSources) >= maxUnknownSources {
				deviceIP = unknownSourceOverflow
			} else {
				t.unknownSources[deviceIP] = struct{}{}
			}
		}
	}
	t.received[receivedKey{deviceIP, policy, trapName, v}]++
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

func (t *Tally) datagramCount() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.datagrams
}
