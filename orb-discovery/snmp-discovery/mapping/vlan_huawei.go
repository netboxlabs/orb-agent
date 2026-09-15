package mapping

import (
	"encoding/hex"
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

// hwVlanPortsCandidates returns every reading an hwVlanPorts value admits.
//
// The MIB declares raw octets; a real MA5608T instead returns those octets
// spelled out as hexadecimal text (an octet string of ASCII '0'..'F', twice
// the bitmap's length). The two forms have no in-band discriminator: a raw
// bitmap whose every octet happens to fall in the ASCII ranges of the hex
// digits — 0x30..0x39, 0x41..0x46, 0x61..0x66 — is also well-formed hex
// text of half the length. So this function does not choose. It returns
// the raw reading whenever the length is a whole number of slots, and the
// text reading as well whenever the value parses as hex text, and the
// caller settles which one the device meant against the device's own port
// inventory (see resolveHuaweiPortList).
//
// A value that admits neither reading — odd length, or a length that is
// not a whole number of slots under either form — yields no candidates and
// the caller refuses it: a misread bitmap would attach VLANs to the wrong
// ports.
func hwVlanPortsCandidates(raw string) [][]slotPort {
	var out [][]slotPort
	octets := []byte(raw)
	if len(octets) > 0 && len(octets)%hwVlanPortsOctetsPerSlot == 0 {
		out = append(out, expandHuaweiPortBitmap(octets))
	}
	if isHexText(octets) {
		if decoded, err := hex.DecodeString(raw); err == nil && len(decoded)%hwVlanPortsOctetsPerSlot == 0 {
			out = append(out, expandHuaweiPortBitmap(decoded))
		}
	}
	return out
}

// expandHuaweiPortBitmap lists the slot/port positions whose bit is set,
// reading the octets the way the MIB's DESCRIPTION lays them out: slot
// b/8 for octet b, ports (b%8)*8 .. (b%8)*8+7 ascending from the LOW bit.
func expandHuaweiPortBitmap(octets []byte) []slotPort {
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
	return out
}

// isHexText reports whether every byte is a hexadecimal digit and the
// length is even.
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

// resolveHuaweiPortList settles which reading of an hwVlanPorts value the
// device meant, by asking which one names only ports the device has.
//
// Exactly one candidate whose every set bit resolves to a walked physical
// port is the answer. None resolving means the bitmap is being read
// wrongly, or a frame is unaccounted for. Both resolving is possible only
// when a raw bitmap is also valid hex text AND both readings happen to land
// on real ports — contrived, but then the value is ambiguous and is
// refused rather than guessed at. An all-zero reading resolves trivially
// (it names no ports) and is the answer for a VLAN with no uplink ports.
//
// The device's port inventory is the discriminator because it is the one
// fact the bitmap has to agree with whichever way it is encoded; it is also
// what rejects the RFC PortList bit order — read MSB-first, the reporting
// device's bits land on a clock port and a port its board does not have.
func resolveHuaweiPortList(candidates [][]slotPort, index map[slotPort]int) (ports []slotPort, resolved bool, ambiguous bool) {
	var matches [][]slotPort
	for _, c := range candidates {
		ok := true
		for _, p := range c {
			if _, found := index[p]; !found {
				ok = false
				break
			}
		}
		if ok {
			matches = append(matches, c)
		}
	}
	switch len(matches) {
	case 0:
		return nil, false, false
	case 1:
		return matches[0], true, false
	}
	// Two readings that both resolve and describe the same ports are one
	// reading (an all-zero value reads as empty either way).
	if samePorts(matches[0], matches[1]) {
		return matches[0], true, false
	}
	return nil, false, true
}

func samePorts(a, b []slotPort) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[slotPort]bool, len(a))
	for _, p := range a {
		set[p] = true
	}
	for _, p := range b {
		if !set[p] {
			return false
		}
	}
	return true
}

// huaweiPortNamePattern matches the ifName Huawei access platforms give a
// physical port: a type word, optional space, then frame/slot/port —
// "ethernet0/2/0", "GPON 0/0/3", "bits0/2/4". The type word may start
// with digits ("10GE0/19/0", "40GE0/9/0") but must contain a letter, so a
// bare "0/2/0" is not taken for a port. Logical interfaces ("vlanif682",
// "meth0", "InLoopBack0") do not match and are not ports.
var huaweiPortNamePattern = regexp.MustCompile(`^[0-9]*[A-Za-z][A-Za-z0-9\-]*\s?(\d+)/(\d+)/(\d+)$`)

// huaweiPortIndex maps slot/port to ifIndex by parsing the walked ifName
// rows. It returns ok=false when the map cannot be trusted: no physical
// port names at all, or ports on more than one frame. hwVlanPorts carries
// no frame, so on a multi-frame chassis a slot/port pair is ambiguous even
// when the frames' slot/port sets happen not to overlap — which is why the
// frame is checked directly rather than inferred from duplicate keys.
func huaweiPortIndex(all ObjectIDValueMap) (map[slotPort]int, bool) {
	idx := map[slotPort]int{}
	frames := map[int]bool{}
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
		frame, _ := strconv.Atoi(m[1])
		slot, _ := strconv.Atoi(m[2])
		port, _ := strconv.Atoi(m[3])
		frames[frame] = true
		if len(frames) > 1 {
			return nil, false
		}
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
// The whole device is refused — nil returned, reason logged — when any
// VLAN's value cannot be settled against the device's port inventory (see
// resolveHuaweiPortList), or when ifName gives no usable slot/port map. One
// wrong association is worse than none.
func huaweiTaggedMembership(all ObjectIDValueMap, logger *slog.Logger) map[int][]int {
	type row struct {
		vid        int
		candidates [][]slotPort
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
		candidates := hwVlanPortsCandidates(v.Value)
		if len(candidates) == 0 {
			logger.Warn("huawei vlan: refusing port membership; hwVlanPorts is not a whole number of 8-octet slots",
				"vid", vid, "length", len(v.Value))
			return nil
		}
		rows = append(rows, row{vid: vid, candidates: candidates})
	}
	if len(rows) == 0 {
		return nil
	}
	index, ok := huaweiPortIndex(all)
	if !ok {
		logger.Warn("huawei vlan: refusing port membership; ifName does not give a usable slot/port map",
			"reason", "no-physical-port-names-or-more-than-one-frame")
		return nil
	}
	out := map[int][]int{}
	for _, r := range rows {
		ports, resolved, ambiguous := resolveHuaweiPortList(r.candidates, index)
		switch {
		case ambiguous:
			logger.Warn("huawei vlan: refusing port membership; hwVlanPorts reads as both raw octets and hex text and both name real ports",
				"vid", r.vid)
			return nil
		case !resolved:
			logger.Warn("huawei vlan: refusing port membership; a set bit names a port the device does not have",
				"vid", r.vid)
			return nil
		}
		for _, p := range ports {
			out[index[p]] = append(out[index[p]], r.vid)
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
