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

// vlanIfIndexBase is the ifIndex of VLAN 1's interface on switches that name
// each VLAN interface by its bare VLAN ID (Eltex MES 21xx/23xx, Cisco small
// business, UniFi); VLAN n's is vlanIfIndexBase + n - 1.
const vlanIfIndexBase = 100000

// ifTypePropVirtual is IANAifType propVirtual(53).
const ifTypePropVirtual = "53"

// numericSviVlanID reads the VLAN of an interface the switch names with the
// bare VLAN ID, as Eltex MES 21xx/23xx, Cisco small-business and UniFi
// switches do. A bare number is no SVI name in general, so it is read only
// where the whole layout holds, on any vendor: ifIndex vlanIfIndexBase +
// VID - 1, ifName and ifDescr both exactly the VID, and ifType
// propVirtual(53). Across the librenms recordings that layout picks out only
// VLAN interfaces.
func numericSviVlanID(oids ObjectIDValueMap, idx int) (int, bool) {
	vid := idx - vlanIfIndexBase + 1
	if vid < 1 || vid > 4094 {
		return 0, false
	}
	id, want := strconv.Itoa(idx), strconv.Itoa(vid)
	for _, col := range []string{oidIfName, oidIfDescr} {
		if v, ok := oids[col+id]; !ok || trimSNMPString(v.Value) != want {
			return 0, false
		}
	}
	if v, ok := oids[oidIfType+id]; !ok || trimSNMPString(v.Value) != ifTypePropVirtual {
		return 0, false
	}
	return vid, true
}

// ResolveSviVlans maps ifIndex to the VLAN an SVI-style interface belongs to.
//
// Only VLANs the DEVICE configures are eligible: a VID its own VLAN tables
// report (deviceVlanVids), named or not. Eligibility is decided by re-reading
// those tables rather than by inspecting the entity, because ensureVLAN stubs
// a VID only an interface's membership references under the same "VLAN<vid>"
// placeholder emitVLANs gives a configured VLAN the device left unnamed, so
// the entity alone cannot tell them apart. A configured unnamed VLAN
// qualifies: the prefix refers to the entity already emitted for it, so the
// association sends no name the run was not sending anyway.
//
// deviceVlanVids is a pure, side-effect-free read of the same rows emission
// consumes, and the set emitVLANs emits from; it never stubs.
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
	configured := deviceVlanVids(oids)
	nameConflicts := vlanNameConflicts(oids)
	eligible := map[int]*diode.VLAN{}
	for _, e := range entities {
		v, ok := e.(*diode.VLAN)
		if !ok || v == nil || v.Vid == nil {
			continue
		}
		vid := int(*v.Vid)
		if _, ok := configured[vid]; !ok {
			continue
		}
		if nameConflicts[vid] {
			logger.Warn("svi vlan: vid named differently across vtp domains; not associating",
				"vid", vid)
			continue
		}
		eligible[vid] = v
	}
	if len(eligible) == 0 {
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
		// ifName and ifDescr can both name one interface. Taking whichever
		// parses first would let collection order pick the VLAN, so require the
		// sources that do parse to agree: two different VLAN ids mean the
		// device's own columns disagree about what this interface is, and there
		// is nothing left to corroborate. This is the same unanimity the
		// aggregate association applies across interfaces, one level down.
		vids := map[int]struct{}{}
		for _, name := range names {
			if vid, ok := sviVlanID(name); ok {
				vids[vid] = struct{}{}
			}
		}
		if vid, ok := numericSviVlanID(oids, idx); ok {
			vids[vid] = struct{}{}
		}
		if len(vids) > 1 {
			logger.Warn("svi vlan: interface names disagree on the vlan id; not associating",
				"ifIndex", idx, "interfaces", names)
			continue
		}
		for vid := range vids {
			vlan, known := eligible[vid]
			if !known {
				logger.Debug("svi vlan: parsed vid absent from the device VLAN database; not associating",
					"ifIndex", idx, "interfaces", names, "vid", vid)
				continue
			}
			out[idx] = vlan
		}
	}
	return out
}
