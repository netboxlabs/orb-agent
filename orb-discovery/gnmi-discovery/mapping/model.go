package mapping

import (
	"reflect"
	"sort"
	"strings"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/gnmi"
)

// DeviceModel is the reconciled in-memory state of one target. Pruning is
// last-seen-cycle based (a TTL in "cycles"), NOT a hard per-window snapshot:
// a path survives as long as it was seen within the last `keep` cycles. This is
// robust to SAMPLE ticks that land mid-cycle and to a target going briefly quiet
// — neither of which should wipe a good model (HIGH-A / MED-B). A "cycle" is a
// sync_response (ON_CHANGE), a sample interval (SAMPLE), or a Get (GET).
type DeviceModel struct {
	values   map[string]any
	lastSeen map[string]int64 // path -> cycle number when last updated
	cycle    int64            // current cycle (advanced by EndCycle)
}

// NewDeviceModel returns an empty model positioned at cycle 1.
func NewDeviceModel() *DeviceModel {
	return &DeviceModel{values: map[string]any{}, lastSeen: map[string]int64{}, cycle: 1}
}

// Apply folds a notification into the model, stamping updated paths as seen in
// the current cycle. Returns true if any value changed.
func (m *DeviceModel) Apply(n gnmi.Notification) bool {
	changed := false
	for _, u := range n.Updates {
		m.lastSeen[u.Path] = m.cycle
		old, ok := m.values[u.Path]
		if !ok || !valuesEqual(old, u.Value) {
			m.values[u.Path] = u.Value
			changed = true
		}
	}
	for _, d := range n.Deletes {
		if m.deletePath(d) {
			changed = true
		}
	}
	return changed
}

// SeenInCycle reports whether path was updated during the current (not-yet-ended)
// cycle. The runner uses this on the device-anchor path to decide whether a
// cycle produced a trustworthy full view before pruning (MED-B guard).
func (m *DeviceModel) SeenInCycle(path string) bool {
	return m.lastSeen[path] == m.cycle
}

// deletePath removes an exact path AND its whole subtree. A gNMI delete can
// target a container or list entry (e.g. /interfaces/interface[name=Eth1] or
// the whole /interfaces/interface list), in which case every descendant leaf
// must be removed too. Children appear with the deleted path followed by
// "/" (sub-leaf) or "[" (list entry). Returns true if anything was removed.
func (m *DeviceModel) deletePath(d string) bool {
	changed := false
	remove := func(k string) {
		delete(m.values, k)
		delete(m.lastSeen, k)
		changed = true
	}
	if _, ok := m.values[d]; ok {
		remove(d)
	}
	childSlash := d + "/"
	childList := d + "["
	for k := range m.values {
		if strings.HasPrefix(k, childSlash) || strings.HasPrefix(k, childList) {
			remove(k)
		}
	}
	return changed
}

// valuesEqual compares two decoded gNMI values without panicking on
// non-comparable types (a JSON_IETF container leaf can decode to a map or
// slice, on which `==` panics). Scalars compare directly; everything else
// uses reflect.DeepEqual (stable for maps/slices, unlike a formatted string).
func valuesEqual(a, b any) bool {
	if isComparable(a) && isComparable(b) {
		return a == b
	}
	return reflect.DeepEqual(a, b)
}

func isComparable(v any) bool {
	switch v.(type) {
	case nil, bool, string,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64:
		return true
	default:
		return false
	}
}

// EndCycle closes the current cycle and advances to the next. When prune is
// true it removes every path not seen within the last `keep` cycles and returns
// them (sorted); when false it advances the cycle without pruning (used by the
// runner's empty-view guard so a partial/empty cycle never wipes the model).
// keep>=1; keep==1 means "must be seen this cycle", keep==2 tolerates one
// missed cycle (the default for SAMPLE, whose ticks may not align with cycles).
func (m *DeviceModel) EndCycle(keep int64, prune bool) []string {
	var pruned []string
	if prune {
		if keep < 1 {
			keep = 1
		}
		cutoff := m.cycle - keep + 1 // keep the current cycle and keep-1 prior
		for p, seen := range m.lastSeen {
			if seen < cutoff {
				pruned = append(pruned, p)
			}
		}
		sort.Strings(pruned)
		for _, p := range pruned {
			delete(m.values, p)
			delete(m.lastSeen, p)
		}
	}
	m.cycle++
	return pruned
}

// BeginSync advances to a new cycle WITHOUT pruning, so the initial full dump of
// a fresh subscription (first connect OR a reconnect) is stamped in its own
// generation, distinct from any steady-state ON_CHANGE updates applied under the
// previous connection. Without this, a reconnect's dump shares the prior cycle:
// an object deleted while the stream was down keeps lastSeen == that shared
// cycle, so the post-sync EndCycle(keep=1) sees it as "still current" and never
// prunes it — leaving departed interfaces/IPs/modules ingested until a later
// reconnect happens to advance the generation. Pruning of the now-stale paths
// happens at the matching EndCycle once the new dump has re-stamped survivors.
func (m *DeviceModel) BeginSync() {
	m.cycle++
}

// Snapshot returns a copy of the current path→value map.
func (m *DeviceModel) Snapshot() map[string]any {
	out := make(map[string]any, len(m.values))
	for k, v := range m.values {
		out[k] = v
	}
	return out
}
