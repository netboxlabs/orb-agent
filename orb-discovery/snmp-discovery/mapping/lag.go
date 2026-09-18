package mapping

import (
	"log/slog"
	"slices"
	"strconv"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

// IEEE8023-LAG-MIB dot3adAggPortTable, indexed by the member port's
// ifIndex. Both columns name an aggregator by its ifIndex; zero means the
// port is not attached to (or has not selected) one.
const (
	oidDot3adAggPortSelectedAggID = ".1.2.840.10006.300.43.1.2.1.1.12."
	oidDot3adAggPortAttachedAggID = ".1.2.840.10006.300.43.1.2.1.1.13."
)

// netboxLagType is the NetBox interface type an aggregator must carry for
// another interface's lag reference to resolve to it.
const netboxLagType = "lag"

// LagMembershipMapper satisfies the orbToEntityMapper interface for the
// "lag_membership" pseudo-entity. Map is a no-op: the aggregator columns
// are consumed wholesale by AttachLagMembership via the raw oids map,
// mirroring the chassis_inventory / vrf pseudo-mappers.
type LagMembershipMapper struct {
	logger *slog.Logger
}

// Map is the row-scoped no-op required by the orbToEntityMapper interface.
func (m *LagMembershipMapper) Map(
	_ map[ObjectIDIndex]*ObjectIDValue,
	_ *Entry,
	_ *EntityRegistry,
	_ *config.Defaults,
) diode.Entity {
	return nil
}

// lagMembershipRows reads dot3adAggPortTable into member ifIndex ->
// aggregator ifIndex, sorted by member ifIndex for deterministic
// application. dot3adAggPortAttachedAggID is the port's current attachment
// and wins where present; dot3adAggPortSelectedAggID stands in for it on
// agents that publish only the selection column. Rows whose winning column
// is zero, or not an integer, are dropped: zero is the MIB's "not attached"
// and inventing a membership from it would be wrong on every device.
func lagMembershipRows(oids ObjectIDValueMap) [][2]int {
	agg := map[int]int{}
	read := func(prefix string, override bool) {
		for oid, v := range oids {
			if !strings.HasPrefix(oid, prefix) {
				continue
			}
			member, err := strconv.Atoi(strings.TrimPrefix(oid, prefix))
			if err != nil || member <= 0 {
				continue
			}
			if _, have := agg[member]; have && !override {
				continue
			}
			id, err := strconv.Atoi(trimSNMPString(v.Value))
			if err != nil {
				continue
			}
			agg[member] = id
		}
	}
	read(oidDot3adAggPortSelectedAggID, false)
	read(oidDot3adAggPortAttachedAggID, true)

	rows := make([][2]int, 0, len(agg))
	for member, id := range agg {
		if id <= 0 {
			continue
		}
		rows = append(rows, [2]int{member, id})
	}
	slices.SortFunc(rows, func(a, b [2]int) int { return a[0] - b[0] })
	return rows
}

// lagMemberTarget picks the interface that carries the lag reference for
// a member row. NetBox refuses a LAG parent on a virtual interface, and on
// Junos the aggregation port the MIB names is the logical unit
// (xe-0/0/0.0), so a member that is itself a subinterface is normalised to
// its physical parent by name, the same derivation
// ResolveSubinterfaceParents uses. A member with no parent is used as-is.
// Returns nil, with a reason, when nothing eligible exists: a virtual
// member whose parent is not in the walk, or a parent name that matches
// more than one interface on the device, which happens on stacks that
// repeat a management port name per member.
func lagMemberTarget(member *diode.Interface, byName map[string][]*diode.Interface) (*diode.Interface, string) {
	if member == nil || member.Name == nil {
		return nil, "member interface has no name"
	}
	parent, isSub, reason := parentInterfaceFor(*member.Name, byName)
	switch {
	case parent != nil:
		return parent, ""
	case isSub && reason == "parent interface name is ambiguous on this device":
		return nil, reason
	}
	// Either not a subinterface at all, or one whose parent is absent: the
	// member itself is the only candidate, and it is eligible only when
	// NetBox would accept a LAG parent on it.
	if isVirtualInterfaceType(member.Type) {
		if isSub {
			return nil, "virtual member's parent interface is not in the walk"
		}
		return nil, "member is a virtual interface with no physical parent"
	}
	return member, ""
}

// isVirtualInterfaceType reports whether t is one of the NetBox types a
// LAG parent may not be assigned to.
func isVirtualInterfaceType(t *string) bool {
	if t == nil {
		return false
	}
	switch *t {
	case "virtual", "bridge", "lag":
		return true
	}
	return false
}

// AttachLagMembership sets Interface.Lag on each physical member port
// named by IEEE8023-LAG-MIB dot3adAggPortTable, pointing at the aggregate
// interface the same walk discovered. ifIndexByIface is the registry's
// interface -> ifIndex map, which covers every interface the mapper built,
// including ones excluded from top-level emission.
//
// Nothing is created: an aggregator that is not in the walk, or that the
// mapper did not type as lag, leaves its members untouched with a warning,
// as does a member that cannot be normalised to an eligible interface (see
// lagMemberTarget). Several logical units of one physical port attached to
// the same aggregate collapse to one reference; a physical port whose units
// name two different aggregates is contradictory and is left without a lag
// rather than picking one.
//
// Must run after TranslateAsStack so Device pointers on both member and
// aggregate already name the owning stack member; the lag reference is
// reduced to a matcher stub by PruneNestedRefs like Parent and Bridge.
// Returns the number of interfaces that received a lag reference.
func AttachLagMembership(
	oids ObjectIDValueMap,
	ifIndexByIface map[*diode.Interface]int,
	logger *slog.Logger,
) int {
	rows := lagMembershipRows(oids)
	if len(rows) == 0 || len(ifIndexByIface) == 0 {
		return 0
	}

	byIfIndex := make(map[int]*diode.Interface, len(ifIndexByIface))
	ifaces := make([]*diode.Interface, 0, len(ifIndexByIface))
	for iface, idx := range ifIndexByIface {
		byIfIndex[idx] = iface
		ifaces = append(ifaces, iface)
	}
	byName := interfacesByName(ifaces)

	// target -> aggregate chosen for it; a second, different aggregate for
	// the same target marks the target contradictory.
	chosen := map[*diode.Interface]*diode.Interface{}
	contradictory := map[*diode.Interface]bool{}
	for _, row := range rows {
		memberIdx, aggIdx := row[0], row[1]
		member, ok := byIfIndex[memberIdx]
		if !ok {
			logger.Warn("lag: member port not in the interface walk; skipping",
				"member_ifindex", memberIdx, "aggregate_ifindex", aggIdx)
			continue
		}
		agg, ok := byIfIndex[aggIdx]
		if !ok {
			logger.Warn("lag: aggregate interface not in the interface walk; skipping member",
				"member", strDeref(member.Name), "aggregate_ifindex", aggIdx)
			continue
		}
		if agg.Type == nil || *agg.Type != netboxLagType {
			logger.Warn("lag: aggregate interface is not typed lag; skipping member",
				"member", strDeref(member.Name), "aggregate", strDeref(agg.Name),
				"aggregate_type", strDeref(agg.Type))
			continue
		}
		target, reason := lagMemberTarget(member, byName)
		if target == nil {
			logger.Warn("lag: no eligible interface to carry the membership; skipping member",
				"member", strDeref(member.Name), "aggregate", strDeref(agg.Name), "reason", reason)
			continue
		}
		if target == agg {
			logger.Warn("lag: member resolves to its own aggregate; skipping",
				"member", strDeref(member.Name), "aggregate", strDeref(agg.Name))
			continue
		}
		if prev, seen := chosen[target]; seen && prev != agg {
			if !contradictory[target] {
				logger.Warn("lag: physical port's units name different aggregates; leaving lag unset",
					"interface", strDeref(target.Name),
					"aggregates", []string{strDeref(prev.Name), strDeref(agg.Name)})
			}
			contradictory[target] = true
			continue
		}
		chosen[target] = agg
	}

	attached := 0
	for target, agg := range chosen {
		if contradictory[target] {
			continue
		}
		target.Lag = &diode.Interface{
			Name:   agg.Name,
			Type:   agg.Type,
			Device: agg.Device,
		}
		attached++
	}
	if attached > 0 {
		logger.Info("lag: attached members to aggregates", "members", attached, "rows", len(rows))
	}
	return attached
}
