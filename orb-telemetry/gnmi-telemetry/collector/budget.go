package collector

import (
	"sync"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/metrics"
)

// Budget is the per-metric-name series bound. It belongs to the process, not
// to a collector: the bound exists to keep the SDK from folding a series the
// backend chose into its overflow set, and the SDK holds one instrument per
// metric name however many collectors write to it. A manager builds one
// collector per profile set, so a bound held per collector would let two
// profile sets each admit the full allowance of if_in_octets and hand that one
// instrument twice what it accepts, losing the device_ip and policy attributes
// the bound is there to protect. Safe for concurrent use.
type Budget struct {
	mu      sync.Mutex
	perName map[string]int
	limit   int
}

// NewBudget returns a budget bounded one series below the SDK's cardinality
// limit per metric name, so the backend never hands the SDK a series it would
// fold.
func NewBudget() *Budget {
	return newBudget(metrics.CardinalityLimit - 1)
}

func newBudget(limit int) *Budget {
	return &Budget{perName: map[string]int{}, limit: limit}
}

// take charges one series to a metric name and reports whether the name had
// room for it. A refusal charges nothing.
func (b *Budget) take(name string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.perName[name] >= b.limit {
		return false
	}
	b.perName[name]++
	return true
}

// release returns one series' slot to its metric name, for the next series of
// that name to take.
func (b *Budget) release(name string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.perName[name]--
}
