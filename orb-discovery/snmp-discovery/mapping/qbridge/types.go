// Package qbridge implements vendor-neutral switchport↔VLAN classification.
//
// The package contract is small: each driver's "extract" function builds a
// SwitchportInfo from raw SNMP rows, and Classify returns the per-port
// Classification consumed by VlanMapper. This mirrors device-discovery
// PR #378's _vlan.py: vendor knowledge lives in the extractor, classification
// is a pure function with no SNMP dependencies.
package qbridge

// Mode is the per-interface classification result emitted by Classify.
type Mode int

const (
	// ModeUnknown — the classifier cannot positively determine this
	// interface's role (e.g., absent from the bridge port table). Distinct
	// from ModeRouted: "we don't know" vs "we know it's L3".
	ModeUnknown Mode = iota
	// ModeAccess — single untagged VLAN, no tagged.
	ModeAccess
	// ModeTrunk — explicit set of tagged VLANs + optional native untagged.
	ModeTrunk
	// ModeTrunkAll — trunk carrying every active VLAN (membership covers 1..4094).
	ModeTrunkAll
	// ModeRouted — positive routed signal (in bridge table but no membership +
	// L3-able ifType). VlanMapper emits no Interface mutation.
	ModeRouted
)

// String returns a human-readable mode for logs and tests.
func (m Mode) String() string {
	switch m {
	case ModeAccess:
		return "access"
	case ModeTrunk:
		return "trunk"
	case ModeTrunkAll:
		return "trunk-all"
	case ModeRouted:
		return "routed"
	default:
		return "unknown"
	}
}

// AdminMode mirrors the configured "switchport mode" intent. Sourced from
// vendor-specific rows in extract_*.go. AdminUnknown means the extractor
// could not determine intent.
type AdminMode int

// Admin modes — extractor-supplied intent. AdminUnknown means the
// extractor couldn't determine intent and the classifier falls back
// to OperMode.
const (
	AdminUnknown AdminMode = iota
	AdminAccess
	AdminTrunk
	AdminDynamic
)

// OperMode is the operational/negotiated mode (DTP fallback for Cisco). For
// non-DTP vendors this typically mirrors AdminMode.
type OperMode int

// Operational modes — observed/negotiated state from the device.
// OperUnknown means the device didn't report an operational mode.
const (
	OperUnknown OperMode = iota
	OperAccess
	OperTrunk
	OperRouted
)

// AllowedVlans is the trunk-allowed VID set. IsWildcard signals "all 1..4094",
// which Classify converts to ModeTrunkAll.
type AllowedVlans struct {
	Vids       []int
	IsWildcard bool
}

// SwitchportInfo is the vendor-neutral intermediate representation. Each
// extractor produces one SwitchportInfo per ifIndex. Classify consumes it
// and returns Classification.
type SwitchportInfo struct {
	Enabled           bool
	AdminMode         AdminMode
	OperMode          OperMode
	AccessVlan        *int
	NativeVlan        *int
	AllowedVlans      AllowedVlans
	VoiceVlan         *int
	BridgePortPresent bool
}

// Classification is the per-interface output VlanMapper consumes to mutate
// diode.Interface entities.
type Classification struct {
	Mode     Mode
	Tagged   []int
	Untagged *int
}

// intPtr is a package-private helper for building *int literals in tests
// and extractors. Returns a pointer to a fresh copy of v so callers can
// freely take addresses of loop variables.
func intPtr(v int) *int {
	return &v
}
