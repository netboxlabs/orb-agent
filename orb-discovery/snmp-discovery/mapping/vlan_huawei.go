package mapping

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// HUAWEI-VLAN-MIB hwVlanMIBEntry columns. Walked only on Huawei.
//
// Huawei access platforms (SmartAX MA5600T/MA5608T OLTs) implement no
// Q-BRIDGE-MIB at all and publish their VLAN database only here. The table
// is indexed by hwVlanIndex, which IS the 802.1Q tag, so the OID suffix is
// the VID. hwVlanName is optional per row — a VLAN with no configured
// description has an index row and no name row — so the index column is
// what establishes which VLANs exist. hwVlanRowStatus is a standard
// RowStatus.
//
// hwVlanPorts (column 3) is the per-VLAN port membership. It is not the RFC
// PortList it is declared as: the column's own DESCRIPTION lays it out as
// eight octets per slot, sixty-four ports per slot, slots in ascending order
// from the left, and within each octet the port IDs ascending from the LOW
// bit. So bit i of octet b names slot b/8, port (b%8)*8+i. These devices
// expose no dot1dBasePortIfIndex, so the slot/port pair is translated
// through ifName instead — see huaweiPortIndex.
const (
	oidHwVlanIndex     = ".1.3.6.1.4.1.2011.5.6.1.1.1.1."
	oidHwVlanName      = ".1.3.6.1.4.1.2011.5.6.1.1.1.2."
	oidHwVlanPorts     = ".1.3.6.1.4.1.2011.5.6.1.1.1.3."
	oidHwVlanRowStatus = ".1.3.6.1.4.1.2011.5.6.1.1.1.13."

	// hwVlanPortsOctetsPerSlot is the MIB's fixed slot stride: 64 ports
	// per slot, one bit each.
	hwVlanPortsOctetsPerSlot = 8
)

// vlanCatalog is the vendor-neutral shape a private VLAN table is reduced
// to before the generic emission path reads it. Vendor extractors produce
// one; VlanMapper consumes it without knowing which MIB it came from.
//
// Vids lists every VLAN the table reports, named or not. Names holds the
// device-supplied name per VID, already stripped of NUL padding and
// whitespace; a VID absent from Names had no name row (or an empty one).
// RowStatus holds the RowStatus value per VID where the table exposes one.
type vlanCatalog struct {
	Vids      map[int]bool
	Names     map[int]string
	RowStatus map[int]int
}

func newVlanCatalog() vlanCatalog {
	return vlanCatalog{
		Vids:      map[int]bool{},
		Names:     map[int]string{},
		RowStatus: map[int]int{},
	}
}

// empty reports whether the catalog carries no rows at all — the signal
// that the vendor table was not walked or the device did not answer it.
func (c vlanCatalog) empty() bool {
	return len(c.Vids) == 0 && len(c.Names) == 0 && len(c.RowStatus) == 0
}

// merge folds other into c. The catalogs come from tables walked behind
// disjoint vendor gates, so no VID is expected from two sources; if one
// ever is, the first non-empty name and the first status seen are kept.
func (c vlanCatalog) merge(other vlanCatalog) {
	for vid := range other.Vids {
		c.Vids[vid] = true
	}
	for vid, name := range other.Names {
		if held := c.Names[vid]; held == "" {
			c.Names[vid] = name
		}
	}
	for vid, st := range other.RowStatus {
		if _, seen := c.RowStatus[vid]; !seen {
			c.RowStatus[vid] = st
		}
	}
}

// vendorVlanCatalogExtractors are the private VLAN tables the generic
// emission path knows how to fold in. Each is walked only behind its own
// vendor gate (see policy/vendor.go and the vendor-scoped entries in
// policy/mapping.yaml), so on any one host at most one of them answers.
var vendorVlanCatalogExtractors = []func(ObjectIDValueMap) vlanCatalog{
	extractHuaweiVlanCatalog,
}

// vendorVlanCatalog returns every private VLAN catalog walked for the host,
// folded into one.
func vendorVlanCatalog(all ObjectIDValueMap) vlanCatalog {
	out := newVlanCatalog()
	for _, extract := range vendorVlanCatalogExtractors {
		out.merge(extract(all))
	}
	return out
}

// extractHuaweiVlanCatalog reduces the walked hwVlanMIBTable rows to a
// vlanCatalog. It is a pure read: it never stubs and never invents a name.
//
// An hwVlanIndex row registers the VID whatever its value — the row's
// presence is the fact; the value merely repeats the index. An hwVlanName
// row whose value trims to "" is treated as no name, so the VID falls
// through to the same VLAN<vid> default a nameless dot1q row gets.
func extractHuaweiVlanCatalog(all ObjectIDValueMap) vlanCatalog {
	cat := newVlanCatalog()
	for oid, v := range all {
		switch {
		case strings.HasPrefix(oid, oidHwVlanIndex):
			if vid, ok := atoi(strings.TrimPrefix(oid, oidHwVlanIndex)); ok {
				cat.Vids[vid] = true
			}
		case strings.HasPrefix(oid, oidHwVlanName):
			vid, ok := atoi(strings.TrimPrefix(oid, oidHwVlanName))
			if !ok {
				continue
			}
			cat.Vids[vid] = true
			if name := trimSNMPString(v.Value); name != "" {
				cat.Names[vid] = name
			}
		case strings.HasPrefix(oid, oidHwVlanRowStatus):
			vid, ok := atoi(strings.TrimPrefix(oid, oidHwVlanRowStatus))
			if !ok {
				continue
			}
			st, ok := atoi(v.Value)
			if !ok {
				continue
			}
			cat.Vids[vid] = true
			cat.RowStatus[vid] = st
		}
	}
	return cat
}

// slotPort is a physical port position on a Huawei access chassis. The
// frame is deliberately absent: hwVlanPorts carries no frame, and the
// platforms that publish it are single-frame.
type slotPort struct {
	slot, port int
}

func (p slotPort) String() string { return strconv.Itoa(p.slot) + "/" + strconv.Itoa(p.port) }

// decodeHuaweiPortList expands an hwVlanPorts value into the slot/port
// positions whose bit is set.
//
// The value is accepted in either of the two forms agents return it in:
// the raw octets the MIB declares, or those octets spelled out as
// hexadecimal text (a real MA5608T answers the latter: an octet string of
// ASCII '0'..'F' twice the bitmap's length). A value that is neither — odd
// length, or text that is not hexadecimal — is refused rather than guessed
// at, since a misread bitmap would attach VLANs to the wrong ports.
func decodeHuaweiPortList(raw string) ([]slotPort, error) {
	octets := []byte(raw)
	if isHexText(octets) {
		decoded, err := hex.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("hwVlanPorts: %w", err)
		}
		octets = decoded
	}
	if len(octets)%hwVlanPortsOctetsPerSlot != 0 {
		return nil, fmt.Errorf("hwVlanPorts: %d octets is not a whole number of %d-octet slots", len(octets), hwVlanPortsOctetsPerSlot)
	}
	var out []slotPort
	for b, octet := range octets {
		if octet == 0 {
			continue
		}
		slot := b / hwVlanPortsOctetsPerSlot
		base := (b % hwVlanPortsOctetsPerSlot) * 8
		for i := 0; i < 8; i++ {
			if octet&(1<<i) != 0 {
				out = append(out, slotPort{slot: slot, port: base + i})
			}
		}
	}
	return out, nil
}

// isHexText reports whether every byte is a hexadecimal digit and the
// length is even. A raw bitmap only satisfies this if every octet happens
// to fall in '0'..'9', 'A'..'F' or 'a'..'f' — 0x30..0x39, 0x41..0x46,
// 0x61..0x66 — which no all-zero bitmap does (0x00 is not a digit), so a
// bitmap with any empty slot is never mistaken for text. A dense bitmap
// whose every octet lands in those ranges would be, and would decode to
// half its length; the slot-stride check and the interface gate downstream
// then refuse it rather than mis-assign ports.
func isHexText(b []byte) bool {
	if len(b) == 0 || len(b)%2 != 0 {
		return false
	}
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9', c >= 'A' && c <= 'F', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// huaweiPortNamePattern matches the ifName Huawei access platforms give a
// physical port: a type word, optional space, then frame/slot/port —
// "ethernet0/2/0", "GPON 0/0/3", "bits0/2/4". Logical interfaces
// ("vlanif682", "meth0", "InLoopBack0") do not match and are not ports.
var huaweiPortNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9\-]*\s?(\d+)/(\d+)/(\d+)$`)

// huaweiPortIndex maps slot/port to ifIndex by parsing the walked ifName
// rows. It returns ok=false when the map cannot be trusted: no physical
// port names at all, or two interfaces claiming the same slot/port (which
// would mean more than one frame, and the bitmap cannot say which).
func huaweiPortIndex(all ObjectIDValueMap) (map[slotPort]int, bool) {
	idx := map[slotPort]int{}
	for oid, v := range all {
		if !strings.HasPrefix(oid, oidIfName) {
			continue
		}
		ifIndex, ok := atoi(strings.TrimPrefix(oid, oidIfName))
		if !ok {
			continue
		}
		m := huaweiPortNamePattern.FindStringSubmatch(trimSNMPString(v.Value))
		if m == nil {
			continue
		}
		slot, _ := strconv.Atoi(m[2])
		port, _ := strconv.Atoi(m[3])
		key := slotPort{slot: slot, port: port}
		if held, dup := idx[key]; dup && held != ifIndex {
			return nil, false
		}
		idx[key] = ifIndex
	}
	return idx, len(idx) > 0
}

// huaweiTaggedMembership reduces hwVlanPorts to per-interface tagged VLAN
// lists: ifIndex -> sorted VIDs.
//
// Membership is reported as tagged. On these platforms the port-VLAN
// binding this column reflects carries the VLAN tag on the uplink, and the
// device publishes no PVID (HUAWEI-L2IF-MIB is not implemented), so there is
// no source from which an untagged VLAN could be named. The result is the
// same shape the generic classifier gives a trunk whose PVID cannot be
// pinned: mode tagged, tagged_vlans set, untagged_vlan unset.
//
// The whole device is refused — nil returned, reason logged — if any set
// bit does not resolve to a walked physical port. A bit that names a port
// the device does not have means the bitmap is being read wrongly (or a
// frame is unaccounted for), and one wrong association is worse than none.
// This is also what rejects the RFC PortList bit order: read MSB-first, the
// reporting device's bits land on a clock port and a non-existent port.
func huaweiTaggedMembership(all ObjectIDValueMap, logger *slog.Logger) map[int][]int {
	type row struct {
		vid   int
		ports []slotPort
	}
	var rows []row
	for oid, v := range all {
		if !strings.HasPrefix(oid, oidHwVlanPorts) {
			continue
		}
		vid, ok := atoi(strings.TrimPrefix(oid, oidHwVlanPorts))
		if !ok || vid < 1 || vid > 4094 {
			continue
		}
		ports, err := decodeHuaweiPortList(v.Value)
		if err != nil {
			logger.Warn("huawei vlan: refusing port membership", "vid", vid, "error", err)
			return nil
		}
		if len(ports) == 0 {
			continue
		}
		rows = append(rows, row{vid: vid, ports: ports})
	}
	if len(rows) == 0 {
		return nil
	}
	index, ok := huaweiPortIndex(all)
	if !ok {
		logger.Warn("huawei vlan: refusing port membership; ifName does not give a usable slot/port map",
			"reason", "no-physical-port-names-or-duplicate-slot-port")
		return nil
	}
	out := map[int][]int{}
	for _, r := range rows {
		for _, p := range r.ports {
			ifIndex, found := index[p]
			if !found {
				logger.Warn("huawei vlan: refusing port membership; a set bit names a port the device does not have",
					"vid", r.vid, "slot_port", p.String())
				return nil
			}
			out[ifIndex] = append(out[ifIndex], r.vid)
		}
	}
	for ifIndex := range out {
		sort.Ints(out[ifIndex])
	}
	return out
}

// vendorTaggedMembership is the port-membership counterpart of
// vendorVlanCatalog: the private tables that carry per-VLAN port lists
// AND a way to name the ports without BRIDGE-MIB, reduced to
// ifIndex -> tagged VIDs. Consulted only when dot1dBasePortIfIndex is
// absent, so a device that answers the standard tables is classified by
// them alone.
var vendorTaggedMembershipExtractors = []func(ObjectIDValueMap, *slog.Logger) map[int][]int{
	huaweiTaggedMembership,
}

func vendorTaggedMembership(all ObjectIDValueMap, logger *slog.Logger) map[int][]int {
	for _, extract := range vendorTaggedMembershipExtractors {
		if out := extract(all, logger); len(out) > 0 {
			return out
		}
	}
	return nil
}
