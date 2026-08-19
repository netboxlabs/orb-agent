package mapping

import (
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"
)

// sviVlanNameRe matches the interface-name shapes whose trailing integer is
// documented to BE the 802.1Q VLAN ID. Anchored at both ends, one optional
// separator, and the token list is a whitelist rather than a heuristic: a
// trailing-integer parser mis-selects roughly two thirds of the interfaces it
// picks, while this gate selected 234 of 1621 IP-bearing interfaces across 301
// operating-system families with no false positives.
//
// Deliberately absent: br, v, vgi, bvi, bdi, ve, irb and rvi. Those are
// SVI-shaped but their integer is a bridge-group id, a bridge-domain id, a
// virtual-interface id or an operator label, and a device whose VLAN table
// happens to contain the same number would corroborate the wrong association
// rather than catch it.
//
// bdi is the sharpest of those. A Cisco bridge domain carries whatever
// encapsulation its service instances declare, so BDI100 can route
// `encapsulation dot1q 10`. Typing a BDI as a virtual interface is correct and
// unaffected; reading its number as a VLAN ID is not.
var sviVlanNameRe = regexp.MustCompile(
	`(?i)^(?:interface[\s_-]+)?(?:vlan-interface|vlan[\s_-]?id|vlanif|vlan|svi|vl)[\s_-]*0*(\d{1,5})$`,
)

// sviVlanID parses the VLAN ID from an SVI-style interface name. Returns false
// when the name is not an SVI shape, contains a dot, or the parsed value falls
// outside the 1..4094 range NetBox accepts.
//
// The dot exclusion is load-bearing rather than tidiness: a dotted name cannot
// be told apart from stack.slot.port notation or a loopback unit, and no device
// measured reports the 802.1Q encapsulation of a routed subinterface, so there
// is nothing to check such a guess against.
func sviVlanID(name string) (int, bool) {
	name = strings.TrimSpace(name)
	if name == "" || strings.Contains(name, ".") {
		return 0, false
	}
	m := sviVlanNameRe.FindStringSubmatch(name)
	if m == nil {
		return 0, false
	}
	vid, err := strconv.Atoi(m[1])
	if err != nil || vid < 1 || vid > 4094 {
		return 0, false
	}
	return vid, true
}

// ResolveSviVlans maps ifIndex to the VLAN an SVI-style interface belongs to.
//
// Only VLANs the DEVICE named are eligible, and eligibility is decided by
// re-reading the walked VLAN name columns rather than by inspecting the
// entity: emitVLANs defaults a nameless VID to "VLAN<vid>" and ensureVLAN
// stubs unknown VIDs under the same placeholder, so every emitted VLAN
// carries a Name and the name alone cannot tell an operator's VLAN from one
// the agent synthesised. That matters beyond tidiness — a reference that
// matches an existing NetBox VLAN is applied as an update carrying the whole
// payload, so referencing a placeholder named "VLAN1" against a VLAN the
// operator calls "default" renames it.
//
// vlanNamesByVid is a pure, side-effect-free read of the same rows emission
// consumes — it never stubs — so recomputing it here keeps the association
// decoupled from the emission path.
//
// Both ifName and ifDescr are consulted because the interface-name resolver
// prefers ifDescr, and several platforms put a generic string there and the
// real SVI name in ifName.
//
// Callers must NOT substitute ensureVLAN for this lookup: it creates a stub on
// a miss and appends it to the emitted entity list, which turns a
// corroborated association into an invented one.
func ResolveSviVlans(
	oids ObjectIDValueMap,
	entities []diode.Entity,
	logger *slog.Logger,
) map[int]*diode.VLAN {
	deviceNames := vlanNamesByVid(oids)
	named := map[int]*diode.VLAN{}
	for _, e := range entities {
		v, ok := e.(*diode.VLAN)
		if !ok || v == nil || v.Vid == nil {
			continue
		}
		vid := int(*v.Vid)
		if deviceNames[vid] == "" {
			continue
		}
		named[vid] = v
	}
	if len(named) == 0 {
		return nil
	}

	namesByIfIndex := map[int][]string{}
	collect := func(prefix string) {
		for oid, val := range oids {
			if !strings.HasPrefix(oid, prefix) {
				continue
			}
			idx, ok := atoi(strings.TrimPrefix(oid, prefix))
			if !ok {
				continue
			}
			if name := trimSNMPString(val.Value); name != "" {
				namesByIfIndex[idx] = append(namesByIfIndex[idx], name)
			}
		}
	}
	collect(oidIfName)
	collect(oidIfDescr)

	out := map[int]*diode.VLAN{}
	for idx, names := range namesByIfIndex {
		for _, name := range names {
			vid, ok := sviVlanID(name)
			if !ok {
				continue
			}
			vlan, known := named[vid]
			if !known {
				logger.Debug("svi vlan: parsed vid absent from the device VLAN database; not associating",
					"ifIndex", idx, "interface", name, "vid", vid)
				continue
			}
			out[idx] = vlan
			break
		}
	}
	return out
}
