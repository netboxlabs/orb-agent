package mapping

import (
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
)

// VRF discovery table columns, tried in tiers until one yields rows.
// Walk-result keys carry no leading dot.
const (
	// Tier 1 — MPLS-L3VPN-STD-MIB (RFC 4382): the standards path.
	// mplsL3VpnVrfRD is indexed by the VRF name (length-prefixed octets)
	// and its value is the route distinguisher; mplsL3VpnIfVpnClassification
	// (IfConfTable, mplsL3VpnConf 1) is indexed by vrfName + ifIndex and
	// carries the membership.
	oidMplsL3VpnVrfRD  = "1.3.6.1.2.1.10.166.11.1.2.2.1.4"
	oidMplsL3VpnIfConf = "1.3.6.1.2.1.10.166.11.1.2.1.1.2"
	// Tier 2 — the pre-standard MPLS-VPN-MIB (experimental arc), same
	// table shapes; still common on older Cisco IOS.
	oidMplsVpnVrfRDLegacy  = "1.3.6.1.3.118.1.2.2.1.3"
	oidMplsVpnIfConfLegacy = "1.3.6.1.3.118.1.2.1.1.2"
	// Tier 3 — CISCO-VRF-MIB for VRF-lite platforms without the MPLS
	// MIBs. cvVrfName is indexed by an integer VRF id;
	// cvVrfInterfaceType is indexed by vrfId + ifIndex. No RD here.
	oidCvVrfName      = "1.3.6.1.4.1.9.9.711.1.1.1.1.2"
	oidCvVrfInterface = "1.3.6.1.4.1.9.9.711.1.2.1.1.2"
)

// Display-form route distinguishers some agents return instead of the
// RFC 4382 8-byte encoding: "65000:100", "10.1.1.1:55".
var vrfDisplayRdRe = regexp.MustCompile(`^(?:\d+|\d+\.\d+\.\d+\.\d+):\d+$`)

type vrfRecord struct {
	name      string
	rd        string
	ifIndexes map[int]struct{}
}

// VrfMapper satisfies the orbToEntityMapper interface for the "vrf"
// pseudo-entity. Map is a no-op: VRF rows are consumed wholesale by the
// runner-level TranslateVrfs pass via the raw oids map, mirroring the
// chassis_inventory / chassis_module pseudo-mappers.
type VrfMapper struct {
	logger *slog.Logger
}

// Map is the row-scoped no-op required by the orbToEntityMapper interface.
func (m *VrfMapper) Map(
	_ map[ObjectIDIndex]*ObjectIDValue,
	_ *Entry,
	_ *EntityRegistry,
	_ *config.Defaults,
) diode.Entity {
	return nil
}

// TranslateVrfs derives VRF entities and an ifIndex→VRF map from the raw
// walk results, trying the three MIB tiers in order until one yields rows.
// VRF entities are returned sorted by name for deterministic emission; the
// same *diode.VRF pointers appear in the map so attached references and
// standalone entities reconcile identically.
func TranslateVrfs(
	oids ObjectIDValueMap,
	defaults *config.Defaults,
	logger *slog.Logger,
) ([]diode.Entity, map[int]*diode.VRF) {
	records := collectNameIndexedVrfs(oids, oidMplsL3VpnVrfRD, oidMplsL3VpnIfConf, logger)
	if !hasVrfMembership(records) {
		// A tier with VRF rows but zero membership (an agent exposing
		// only the RD table on this arc) still falls through, merging
		// the lower tier's data so split-arc agents keep their
		// interface attachment.
		mergeVrfRecords(records, collectNameIndexedVrfs(oids, oidMplsVpnVrfRDLegacy, oidMplsVpnIfConfLegacy, logger))
	}
	if !hasVrfMembership(records) {
		mergeVrfRecords(records, collectCiscoVrfs(oids, logger))
	}
	if len(records) == 0 {
		return nil, nil
	}

	var tags []*diode.Tag
	if defaults != nil {
		for _, t := range defaults.Tags {
			tagName := t
			tags = append(tags, &diode.Tag{Name: &tagName})
		}
	}

	names := make([]string, 0, len(records))
	for name := range records {
		names = append(names, name)
	}
	sort.Strings(names)

	entities := make([]diode.Entity, 0, len(records))
	byIfIndex := make(map[int]*diode.VRF)
	for _, name := range names {
		rec := records[name]
		vrfName := rec.name
		vrf := &diode.VRF{Name: &vrfName}
		if rec.rd != "" {
			rd := rec.rd
			vrf.Rd = &rd
		}
		if len(tags) > 0 {
			vrf.Tags = tags
		}
		entities = append(entities, vrf)
		for ifIndex := range rec.ifIndexes {
			byIfIndex[ifIndex] = vrf
		}
	}
	return entities, byIfIndex
}

// AttachVrfs overwrites IPAddress VRF references for addresses whose
// assigned interface belongs to a discovered VRF. Discovered membership is
// device state and wins over the configured defaults (which remain the
// fallback for every other address) — mirroring device-discovery's
// precedence. Interfaces outside the map are left untouched.
//
// Device.PrimaryIp4/6 (and the VirtualChassis master-ref stubs derived
// from them during stack translation) hold SNAPSHOT copies of the IP
// taken at map time — before this attach ran — so they are re-synced by
// address here. Without that, the primary-IP reference and the IPAddress
// entity would disagree on the VRF, and NetBox (whose IP identity is
// address+vrf) would create duplicate IPAddress objects.
// AttachVrfs returns the address→VRF map of the attachments it made so
// downstream passes (prefix derivation) can carry the discovered VRF onto
// containers of the same addresses. The map is single-valued per address:
// the SNMP pipeline guarantees one IPAddress entity per address string
// per walk (the IP tables are address-indexed and the modern/legacy
// overlap is deduped), so a conflict can only come from callers handing
// in synthetic entity slices — guarded with first-wins plus a warning so
// it can never silently rewrite snapshots or drop a (prefix, VRF) pair.
func AttachVrfs(
	entities []diode.Entity,
	vrfByIfIndex map[int]*diode.VRF,
	ifIndexByIface map[*diode.Interface]int,
	logger *slog.Logger,
) map[string]*diode.VRF {
	vrfByAddress := make(map[string]*diode.VRF)
	if len(vrfByIfIndex) == 0 || len(ifIndexByIface) == 0 {
		return vrfByAddress
	}
	for _, e := range entities {
		ip, ok := e.(*diode.IPAddress)
		if !ok {
			continue
		}
		iface, ok := ip.AssignedObject.(*diode.Interface)
		if !ok {
			continue
		}
		idx, ok := ifIndexByIface[iface]
		if !ok {
			continue
		}
		if vrf, hit := vrfByIfIndex[idx]; hit {
			ip.Vrf = vrf
			if ip.Address == nil {
				continue
			}
			if existing, dup := vrfByAddress[*ip.Address]; dup && existing != vrf {
				logger.Warn(
					"vrf: same address attached in two VRFs; keeping the first "+
						"for primary-IP sync and prefix derivation",
					"address", *ip.Address,
					"kept", strVal(existing.Name),
					"dropped", strVal(vrf.Name),
				)
				continue
			}
			vrfByAddress[*ip.Address] = vrf
		}
	}
	if len(vrfByAddress) == 0 {
		return vrfByAddress
	}
	syncSnapshot := func(snapshot *diode.IPAddress) {
		if snapshot == nil || snapshot.Address == nil {
			return
		}
		if vrf, ok := vrfByAddress[*snapshot.Address]; ok {
			snapshot.Vrf = vrf
		}
	}
	syncDevice := func(dev *diode.Device) {
		if dev == nil {
			return
		}
		syncSnapshot(dev.PrimaryIp4)
		syncSnapshot(dev.PrimaryIp6)
		if dev.VirtualChassis != nil {
			syncDeviceShallow(dev.VirtualChassis.Master, syncSnapshot)
		}
	}
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.Device:
			syncDevice(v)
		case *diode.VirtualChassis:
			syncDeviceShallow(v.Master, syncSnapshot)
		}
	}
	return vrfByAddress
}

// strVal dereferences a string pointer for logging, tolerating nil.
func strVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// syncDeviceShallow re-syncs the primary-IP stubs on a VC master ref
// without recursing into its own VirtualChassis (master refs are built
// non-recursive by design).
func syncDeviceShallow(dev *diode.Device, syncSnapshot func(*diode.IPAddress)) {
	if dev == nil {
		return
	}
	syncSnapshot(dev.PrimaryIp4)
	syncSnapshot(dev.PrimaryIp6)
}

// collectNameIndexedVrfs reads one RD column (indexed by the VRF name as
// length-prefixed octets) and one IfConf column (indexed by vrfName +
// ifIndex). VRFs appearing only in the membership table are still emitted
// (RD absent) so a partial agent implementation can't hide a VRF.
func collectNameIndexedVrfs(
	oids ObjectIDValueMap,
	rdColumn, ifConfColumn string,
	logger *slog.Logger,
) map[string]*vrfRecord {
	records := make(map[string]*vrfRecord)
	get := func(name string) *vrfRecord {
		rec, ok := records[name]
		if !ok {
			rec = &vrfRecord{name: name, ifIndexes: make(map[int]struct{})}
			records[name] = rec
		}
		return rec
	}
	for oid, value := range oids {
		if suffix, ok := oidSuffix(oid, rdColumn); ok {
			name, decoded := decodeOctetStringIndex(suffix)
			if !decoded {
				logger.Debug("vrf: undecodable VRF-name index, skipping row",
					"oid", oid)
				continue
			}
			rec := get(name)
			rec.rd = decodeRouteDistinguisher(value.Value, logger)
			continue
		}
		if suffix, ok := oidSuffix(oid, ifConfColumn); ok {
			name, tail, decoded := decodeOctetStringIndexWithTail(suffix, 1)
			if !decoded {
				logger.Debug("vrf: undecodable IfConf index, skipping row",
					"oid", oid)
				continue
			}
			get(name).ifIndexes[tail[0]] = struct{}{}
		}
	}
	return records
}

// collectCiscoVrfs reads CISCO-VRF-MIB: cvVrfName (integer VRF id index →
// name) and cvVrfInterfaceType (vrfId + ifIndex index). Membership rows
// whose vrfId has no name row are dropped — there is nothing to attach.
func collectCiscoVrfs(oids ObjectIDValueMap, logger *slog.Logger) map[string]*vrfRecord {
	namesByID := make(map[int]string)
	membersByID := make(map[int]map[int]struct{})
	for oid, value := range oids {
		if suffix, ok := oidSuffix(oid, oidCvVrfName); ok {
			id, err := strconv.Atoi(suffix)
			if err != nil {
				logger.Debug("vrf: non-integer cvVrfId index, skipping row", "oid", oid)
				continue
			}
			// cvVrfName is read as a value (unlike the std/legacy tiers,
			// whose names come from the OID index and are control-rejected
			// by octetsToString). Sanitize NUL padding/whitespace here so a
			// "RED\x00" name both ingests cleanly and matches "RED" from
			// another tier during the cross-tier merge.
			if name := trimSNMPString(value.Value); name != "" {
				namesByID[id] = name
			}
			continue
		}
		if suffix, ok := oidSuffix(oid, oidCvVrfInterface); ok {
			parts := strings.SplitN(suffix, ".", 2)
			if len(parts) != 2 {
				continue
			}
			id, err1 := strconv.Atoi(parts[0])
			ifIndex, err2 := strconv.Atoi(parts[1])
			if err1 != nil || err2 != nil {
				logger.Debug("vrf: undecodable cvVrfInterface index, skipping row", "oid", oid)
				continue
			}
			if membersByID[id] == nil {
				membersByID[id] = make(map[int]struct{})
			}
			membersByID[id][ifIndex] = struct{}{}
		}
	}
	records := make(map[string]*vrfRecord, len(namesByID))
	for id, name := range namesByID {
		rec := &vrfRecord{name: name, ifIndexes: make(map[int]struct{})}
		for ifIndex := range membersByID[id] {
			rec.ifIndexes[ifIndex] = struct{}{}
		}
		records[name] = rec
	}
	return records
}

// oidSuffix returns the index portion of oid under the given table column,
// tolerating a leading dot on either side.
func oidSuffix(oid, column string) (string, bool) {
	oid = strings.TrimPrefix(oid, ".")
	column = strings.TrimPrefix(column, ".")
	if !strings.HasPrefix(oid, column+".") {
		return "", false
	}
	return oid[len(column)+1:], true
}

// decodeOctetStringIndex decodes an SNMP octet-string table index from its
// OID suffix form. See decodeOctetStringIndexWithTail.
func decodeOctetStringIndex(suffix string) (string, bool) {
	name, _, ok := decodeOctetStringIndexWithTail(suffix, 0)
	return name, ok
}

// hasVrfMembership reports whether any record carries interface members.
func hasVrfMembership(records map[string]*vrfRecord) bool {
	for _, rec := range records {
		if len(rec.ifIndexes) > 0 {
			return true
		}
	}
	return false
}

// mergeVrfRecords folds src into dst: membership unions per name and the
// RD keeps dst's value when already set. Names new to dst are adopted
// ONLY when dst is empty — when a higher tier already enumerated the
// VRFs, lower tiers may only refine membership for those names, never
// introduce additional VRFs (e.g. CISCO-VRF-MIB internal iVRFs that the
// standards arc deliberately does not expose).
func mergeVrfRecords(dst, src map[string]*vrfRecord) {
	adoptNew := len(dst) == 0
	for name, srcRec := range src {
		dstRec, ok := dst[name]
		if !ok {
			if adoptNew {
				dst[name] = srcRec
			}
			continue
		}
		if dstRec.rd == "" {
			dstRec.rd = srcRec.rd
		}
		for ifIndex := range srcRec.ifIndexes {
			dstRec.ifIndexes[ifIndex] = struct{}{}
		}
	}
}

// decodeOctetStringIndexWithTail decodes a length-prefixed octet-string
// index followed by tailLen plain integer sub-identifiers (e.g. the
// mplsL3VpnIfConf index: vrfName + ifIndex). When the leading
// sub-identifier doesn't look like a valid length prefix, the IMPLIED
// (unprefixed) encoding is tried as a fallback — agents disagree here.
// Name octets must form valid, control-character-free UTF-8 (RFC 4382's
// mplsL3VpnVrfName is an SnmpAdminString); anything else fails the row.
func decodeOctetStringIndexWithTail(suffix string, tailLen int) (string, []int, bool) {
	parts := strings.Split(suffix, ".")
	ints := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return "", nil, false
		}
		ints[i] = n
	}
	if len(ints) < 1+tailLen {
		return "", nil, false
	}
	// Length-prefixed form: first sub-identifier is the octet count.
	if n := ints[0]; n > 0 && len(ints) == 1+n+tailLen {
		if name, ok := octetsToString(ints[1 : 1+n]); ok {
			return name, ints[1+n:], true
		}
	}
	// IMPLIED form: every leading sub-identifier is a name octet.
	if name, ok := octetsToString(ints[:len(ints)-tailLen]); ok {
		return name, ints[len(ints)-tailLen:], true
	}
	return "", nil, false
}

func octetsToString(octets []int) (string, bool) {
	if len(octets) == 0 {
		return "", false
	}
	b := make([]byte, len(octets))
	for i, o := range octets {
		// Reject raw control bytes and anything outside the byte range;
		// multi-byte UTF-8 sequences are allowed — RFC 4382's
		// mplsL3VpnVrfName is an SnmpAdminString (UTF-8).
		if o < 0x20 || o > 0xff || o == 0x7f {
			return "", false
		}
		b[i] = byte(o)
	}
	if !utf8.Valid(b) {
		return "", false
	}
	// Reject encoded control characters too (C1 range like U+0085
	// arrives as a valid multi-byte sequence the per-octet check above
	// can't see).
	for _, r := range string(b) {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return string(b), true
}

// decodeRouteDistinguisher normalizes an RD value to its display form.
// Agents return either the display string directly or the RFC 4382 8-byte
// encoding (2-byte type, then type-specific fields). Unset / undecodable
// RDs return "" so the rd field stays off the wire and the VRF matches
// NetBox records whose rd column is null.
func decodeRouteDistinguisher(raw string, logger *slog.Logger) string {
	// Some agents pad display-form RDs with whitespace or NULs; classify
	// the display form against a TRIMMED COPY ONLY — the original bytes
	// must reach the binary path untouched, because every RFC 4382
	// binary RD starts with a 0x00 type byte that trimming would eat.
	trimmed := strings.Trim(raw, " \t\r\n\x00")
	if trimmed == "" {
		return ""
	}
	if vrfDisplayRdRe.MatchString(trimmed) {
		return trimmed
	}
	if len(raw) != 8 {
		logger.Debug("vrf: unrecognized RD form, emitting VRF without rd",
			"length", len(raw))
		return ""
	}
	b := []byte(raw)
	allZero := true
	for _, x := range b {
		if x != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return ""
	}
	rdType := int(b[0])<<8 | int(b[1])
	switch rdType {
	case 0: // 2-byte ASN : 4-byte assigned number
		asn := int(b[2])<<8 | int(b[3])
		num := uint32(b[4])<<24 | uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7])
		return fmt.Sprintf("%d:%d", asn, num)
	case 1: // IPv4 address : 2-byte assigned number
		num := int(b[6])<<8 | int(b[7])
		return fmt.Sprintf("%d.%d.%d.%d:%d", b[2], b[3], b[4], b[5], num)
	case 2: // 4-byte ASN : 2-byte assigned number
		asn := uint32(b[2])<<24 | uint32(b[3])<<16 | uint32(b[4])<<8 | uint32(b[5])
		num := int(b[6])<<8 | int(b[7])
		return fmt.Sprintf("%d:%d", asn, num)
	default:
		logger.Debug("vrf: unknown RD type, emitting VRF without rd", "type", rdType)
		return ""
	}
}
