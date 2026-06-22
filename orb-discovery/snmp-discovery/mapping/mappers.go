package mapping

import (
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/data"
)

// Interface speed constants
const (
	minInterfaceSpeed = 0
	maxInterfaceSpeed = 2147483647
)

// MTU constants
const (
	minInterfaceMTU = 1
	maxInterfaceMTU = 2147483647
)

// IPAddressMapper is a struct that maps IP addresses to entities
type IPAddressMapper struct {
	logger *slog.Logger
	// vrfMisconfigWarnOnce fires the "VRF fields set but no Name"
	// warning at most once per mapper lifetime. applyDefaults runs per
	// discovered IP address, so without rate-limiting a misconfigured
	// policy would flood the logs with one identical line per row.
	vrfMisconfigWarnOnce sync.Once
}

// NewIPAddressMapper creates a new IPAddressMapper
func NewIPAddressMapper(logger *slog.Logger) *IPAddressMapper {
	return &IPAddressMapper{
		logger: logger,
	}
}

// applyDefaults applies default values to an IP address entity
func (m *IPAddressMapper) applyDefaults(entity *diode.IPAddress, defaults *config.Defaults) {
	if defaults == nil {
		return
	}
	entityDefaults := defaults.IPAddress

	// Apply entity-specific defaults
	if entityDefaults.Description != "" {
		entity.Description = &entityDefaults.Description
	}
	if entityDefaults.Comments != "" {
		entity.Comments = &entityDefaults.Comments
	}

	// Collect tags from both entity-specific and global defaults
	var tags []*diode.Tag
	if len(entityDefaults.Tags) > 0 {
		for _, tag := range entityDefaults.Tags {
			tags = append(tags, &diode.Tag{Name: &tag})
		}
	}
	if len(defaults.Tags) > 0 {
		for _, tag := range defaults.Tags {
			tags = append(tags, &diode.Tag{Name: &tag})
		}
	}

	// Apply tags if any exist
	if len(tags) > 0 {
		entity.Tags = tags
	}

	// Apply global defaults if not overridden by entity-specific defaults
	if entity.Description == nil && entityDefaults.Description != "" {
		entity.Description = &entityDefaults.Description
	}
	if entity.Comments == nil && entityDefaults.Comments != "" {
		entity.Comments = &entityDefaults.Comments
	}
	if entity.Tenant == nil && entityDefaults.Tenant != "" {
		entity.Tenant = &diode.Tenant{
			Name: &entityDefaults.Tenant,
		}
	}
	if entity.Role == nil && entityDefaults.Role != "" {
		entity.Role = &entityDefaults.Role
	}
	if entity.Vrf == nil {
		// Resolve the per-address-family VRF: vrf_ipv4 / vrf_ipv6 win for
		// their family, falling back to the AF-agnostic vrf. The entity's
		// address is always set before applyDefaults runs (the caller
		// returns early on empty addresses), so the family discriminator
		// is the address literal itself.
		family := "ipv4"
		if entity.Address != nil && strings.Contains(*entity.Address, ":") {
			family = "ipv6"
		}
		vrfDefaults, vrfKnob := entityDefaults.VrfForFamily(family)
		switch {
		case vrfDefaults.Name != "":
			vrf := &diode.VRF{Name: &vrfDefaults.Name}
			if vrfDefaults.Rd != "" {
				vrf.Rd = &vrfDefaults.Rd
			}
			if vrfDefaults.Description != "" {
				vrf.Description = &vrfDefaults.Description
			}
			if vrfDefaults.Comments != "" {
				vrf.Comments = &vrfDefaults.Comments
			}
			if len(vrfDefaults.Tags) > 0 {
				tags := make([]*diode.Tag, 0, len(vrfDefaults.Tags))
				for _, t := range vrfDefaults.Tags {
					tagName := t
					tags = append(tags, &diode.Tag{Name: &tagName})
				}
				vrf.Tags = tags
			}
			entity.Vrf = vrf
		case vrfDefaults.Rd != "", vrfDefaults.Description != "",
			vrfDefaults.Comments != "", len(vrfDefaults.Tags) > 0:
			// One or more VRF sub-fields were configured but Name is empty,
			// either via a policy default like `vrf: {rd: "65000:100"}` with
			// no name OR a per-target override that refines fields without
			// inheriting a policy-level Name. NetBox VRFs match on (name, rd)
			// — there is nothing to attach without Name, so the row is
			// dropped silently in the proto. Surface a warning so the
			// operator sees the misconfiguration in the logs instead of
			// wondering why the IPs have no VRF. Rate-limit to once per
			// mapper lifetime since applyDefaults runs per IP — without
			// this guard a misconfigured policy would emit one identical
			// warning per discovered address.
			m.vrfMisconfigWarnOnce.Do(func() {
				m.logger.Warn(
					fmt.Sprintf(
						"VRF defaults dropped: name is empty but other VRF fields are set; "+
							"set defaults.ip_address.%[1]s.name in the policy (or "+
							"targets[].override_defaults.ip_address.%[1]s.name) to enable VRF emission. "+
							"Note: a per-AF override (vrf_ipv4 / vrf_ipv6) replaces the AF-agnostic "+
							"vrf wholesale for its family — it does not inherit vrf.name. "+
							"This warning is logged once per discovery run; subsequent IPs with the same misconfig will be silently skipped.",
						vrfKnob,
					),
					"knob", vrfKnob,
					"rd", vrfDefaults.Rd,
					"description", vrfDefaults.Description,
					"comments", vrfDefaults.Comments,
					"tags", vrfDefaults.Tags,
				)
			})
		}
	}
}

// Map maps IP addresses to entities
func (m *IPAddressMapper) Map(values map[ObjectIDIndex]*ObjectIDValue, mappingEntry *Entry, entityRegistry *EntityRegistry, defaults *config.Defaults) diode.Entity {
	m.logger.Debug("mapping values to ipAddress entity", "values", values, "mapping_entry", mappingEntry)
	ipAddress := diode.IPAddress{}

	fieldFound := false
	var extractedIP string // Store the IP address extracted from any field

	isInetAddress := mappingEntry.IndexKind == "inet_address"

	// Lenient defaults match the "missing column" semantics so devices
	// that omit one of the filter columns are not rejected.
	addrType := 1   // unicast
	addrStatus := 1 // preferred
	rowStatus := 1  // active

	extractIPFromIndex := func(value *ObjectIDValue, field string) {
		if extractedIP != "" {
			return
		}
		if value.Index == "" {
			return
		}
		raw := stripIndexFamilyPrefix(string(value.Index))
		if ip := net.ParseIP(raw); ip != nil {
			extractedIP = ip.String()
			m.logger.Debug("extracted IP address", "field", field, "ip", extractedIP)
		}
	}

	extractIPFromValueOrIndex := func(value *ObjectIDValue, field string) bool {
		if extractedIP != "" {
			return true // Already extracted
		}
		// Try to extract from value field first
		if value.Value != "" {
			if ip := net.ParseIP(value.Value); ip != nil {
				extractedIP = ip.String()
				m.logger.Debug("extracted IP address", "field", field, "ip", extractedIP)
				return true
			}
		}
		// Fall back to extracting from index
		extractIPFromIndex(value, field)
		return extractedIP != ""
	}

	setOrUpdateAddress := func(newAddress string) {
		ipAddress.Address = &newAddress
	}

	// inet_address-indexed rows derive the address from the (already
	// decoded) index, not from a separate column. Set it once up front
	// with a host-route default; the addressPrefix handler may overwrite.
	if isInetAddress {
		for _, v := range values {
			canonical := stripIndexFamilyPrefix(string(v.Index))
			if canonical == "" {
				continue
			}
			if strings.Contains(canonical, ":") {
				setOrUpdateAddress(fmt.Sprintf("%s/128", canonical))
			} else {
				setOrUpdateAddress(fmt.Sprintf("%s/32", canonical))
			}
			extractedIP = canonical
			fieldFound = true
			break
		}
	}

	for objectID, value := range values {
		m.logger.Debug("mapping value to ipAddress entity", "object_id", objectID, "value", value)
		for _, propertyMappingEntry := range mappingEntry.MappingEntries {
			if objectID.HasParent(propertyMappingEntry.OID) {
				switch propertyMappingEntry.Field {
				case "address":
					if !extractIPFromValueOrIndex(value, propertyMappingEntry.Field) {
						m.logger.Warn("could not extract valid IP address from any field")
						continue
					}
					if ipAddress.Address != nil && strings.HasPrefix(*ipAddress.Address, "/") {
						// Prefix was processed first, prepend IP
						setOrUpdateAddress(fmt.Sprintf("%s%s", extractedIP, *ipAddress.Address))
					} else if ipAddress.Address == nil || *ipAddress.Address == "" {
						// No prefix yet, set IP with default /32
						setOrUpdateAddress(fmt.Sprintf("%s/32", extractedIP))
					}
					fieldFound = true
				case "addressPrefixSize":
					extractIPFromIndex(value, propertyMappingEntry.Field)
					prefixLength, err := maskToPrefixSize(value.Value)
					if err != nil {
						m.logger.Warn("error converting mask to prefix size", "error", err, "value", value.Value)
						continue
					}
					if ipAddress.Address == nil || *ipAddress.Address == "" {
						// No address set yet
						if extractedIP != "" {
							// Use extracted IP with the prefix
							setOrUpdateAddress(fmt.Sprintf("%s/%d", extractedIP, prefixLength))
						} else {
							// No IP available, store just the prefix (will be rejected by validation)
							setOrUpdateAddress(fmt.Sprintf("/%d", prefixLength))
						}
						fieldFound = true
					} else {
						// Address already set, update the prefix
						prefixParts := strings.Split(*ipAddress.Address, "/")
						if len(prefixParts) >= 1 {
							setOrUpdateAddress(fmt.Sprintf("%s/%d", prefixParts[0], prefixLength))
						} else {
							setOrUpdateAddress(fmt.Sprintf("%s/%d", *ipAddress.Address, prefixLength))
						}
						fieldFound = true
					}
				case "addressPrefix":
					// RFC 4293 ipAddressTable .5 is a RowPointer into
					// ipAddressPrefixTable; the last sub-OID is the
					// prefix length. zeroDotZero, malformed pointers,
					// and pointers outside the prefix table fall back
					// to the host-route default already set above.
					if ipAddress.Address == nil || *ipAddress.Address == "" {
						continue
					}
					prefixLen, pointerIsV6, pointerIfIndex, networkBytes, ok := parseAddressPrefixRowPointer(value.Value)
					if !ok {
						m.logger.Debug("addressPrefix not usable, keeping host route",
							"value", value.Value, "address", *ipAddress.Address)
						fieldFound = true
						continue
					}
					canonical := stripPrefix(*ipAddress.Address)
					rowIsV6 := strings.Contains(canonical, ":")
					if pointerIsV6 != rowIsV6 {
						// A row that points at a prefix entry of a
						// different family is structurally invalid
						// (e.g. an IPv6 row pointing at an IPv4
						// prefix entry). Keep the host-route default
						// rather than emitting a wrong prefix.
						m.logger.Debug("addressPrefix family mismatch, keeping host route",
							"value", value.Value, "address", *ipAddress.Address,
							"pointer_v6", pointerIsV6, "row_v6", rowIsV6)
						fieldFound = true
						continue
					}
					// Verify the pointer's <ifIndex> component matches
					// the row's own ipAddressIfIndex. Without this
					// check, a row could silently borrow another
					// interface's prefix length on devices with
					// overlapping subnets. The companion .3 PDU lives
					// at the same row OID with the column bit
					// rewritten from .5 to .3; missing or "0" ifIndex
					// is treated as "no constraint" since the row
					// itself is unbound (per RFC 4293
					// InterfaceIndexOrZero).
					rowIfIndex := lookupSiblingValue(values, value.OID, ".5.", ".3.")
					if rowIfIndex != "" && rowIfIndex != "0" && pointerIfIndex != rowIfIndex {
						m.logger.Debug("addressPrefix ifIndex mismatch, keeping host route",
							"value", value.Value, "address", *ipAddress.Address,
							"pointer_ifindex", pointerIfIndex, "row_ifindex", rowIfIndex)
						fieldFound = true
						continue
					}
					maxLen := 32
					if rowIsV6 {
						maxLen = 128
					}
					// Verify the row's address actually falls within
					// the prefix described by the pointer. RFC 4293
					// indexes ipAddressPrefixTable rows by the
					// network address (host bits zeroed), so a
					// pointer with addrBytes=192.168.0.0/16 attached
					// to a row whose address is 10.0.0.1 is
					// structurally wrong — fall back to the host
					// route rather than emitting a bogus prefix. A
					// length-clamped value is treated as the
					// family's maximum for the containment check.
					checkLen := prefixLen
					if checkLen > maxLen {
						checkLen = maxLen
					}
					if !addressInsidePrefix(canonical, networkBytes, checkLen) {
						m.logger.Debug("addressPrefix points at an unrelated prefix row, keeping host route",
							"value", value.Value, "address", *ipAddress.Address)
						fieldFound = true
						continue
					}
					if prefixLen > maxLen {
						m.logger.Debug("addressPrefix length clamped",
							"raw", prefixLen, "clamped", maxLen, "address", canonical)
						prefixLen = maxLen
					}
					setOrUpdateAddress(fmt.Sprintf("%s/%d", canonical, prefixLen))
					fieldFound = true
				case "assignedObject":
					extractIPFromIndex(value, propertyMappingEntry.Field)
					// RFC 4293 ipAddressIfIndex is InterfaceIndexOrZero;
					// 0 means the address is not associated with any
					// interface (e.g. a globally-scoped address that
					// has not been bound, or a partial walk where the
					// agent could not resolve the binding). Skip the
					// relationship in that case so we don't fabricate
					// a placeholder Interface for ifIndex 0.
					if propertyMappingEntry.Relationship.Type == "interface" && (value.Value == "" || value.Value == "0") {
						m.logger.Debug("ipAddressIfIndex is zero; leaving address unassigned",
							"index", string(value.Index))
						continue
					}
					if propertyMappingEntry.Relationship != (config.Relationship{}) {
						linkedEntity := entityRegistry.GetOrCreateEntity(EntityType(propertyMappingEntry.Relationship.Type), ObjectIDIndex(value.Value))
						if linkedEntity == nil {
							m.logger.Warn("no linked entity found while mapping assigned object", "relationship", propertyMappingEntry.Relationship)
							continue
						}
						// Handle relationship mapping
						if propertyMappingEntry.Relationship.Type == "interface" {
							ipAddress.AssignedObject = linkedEntity.(*diode.Interface)
							fieldFound = true
						}
					}
				case "addressType":
					if n, err := strconv.Atoi(value.Value); err == nil {
						addrType = n
						fieldFound = true
					}
				case "addressStatus":
					if n, err := strconv.Atoi(value.Value); err == nil {
						addrStatus = n
						fieldFound = true
					}
				case "addressRowStatus":
					if n, err := strconv.Atoi(value.Value); err == nil {
						rowStatus = n
						fieldFound = true
					}
				default:
					m.logger.Warn("unknown field",
						"field", propertyMappingEntry.Field,
						"object_id", propertyMappingEntry.OID)
				}
			}
		}
	}

	// Validate the final IP/CIDR before storage. inet_address rows can
	// be IPv4 or IPv6; legacy ipAddrTable rows must remain IPv4.
	if ipAddress.Address != nil && *ipAddress.Address != "" {
		valid := false
		if isInetAddress {
			valid = ValidateIPCIDR(*ipAddress.Address)
		} else {
			valid = ValidateIPv4CIDR(*ipAddress.Address)
		}
		if !valid {
			m.logger.Warn("invalid IP/CIDR format, skipping",
				"address", *ipAddress.Address)
			// Return nil to drop the row outright. An empty
			// &diode.IPAddress{} is still added by MapObjectIDsToEntity
			// (the nil check there is on the entity pointer, not its
			// fields), which would emit a malformed entity downstream.
			return nil
		}
	}

	// RFC 4293 row filtering: drop non-unicast, non-preferred/deprecated,
	// or non-active rows. Returning nil drops the row outright; an empty
	// &diode.IPAddress{} would still be added by MapObjectIDsToEntity.
	if isInetAddress {
		if addrType != 1 {
			m.logger.Debug("dropping non-unicast row", "addrType", addrType, "address", derefAddr(ipAddress.Address))
			return nil
		}
		// Accept preferred(1), deprecated(2), and optimistic(8). The
		// last is "may be used freely with caveats" per RFC 4862;
		// rejecting it while keeping deprecated would be inconsistent.
		// Reject tentative(6) / invalid(3) / inaccessible(4) /
		// unknown(5) / duplicate(7).
		if addrStatus != 1 && addrStatus != 2 && addrStatus != 8 {
			m.logger.Debug("dropping row by status", "status", addrStatus, "address", derefAddr(ipAddress.Address))
			return nil
		}
		if rowStatus != 1 {
			m.logger.Debug("dropping inactive row", "rowStatus", rowStatus, "address", derefAddr(ipAddress.Address))
			return nil
		}
	}

	// An IPAddress entity without a valid Address is meaningless to
	// downstream consumers. Drop it (return nil) so MapObjectIDsToEntity
	// doesn't emit a malformed entity. This covers the case where no
	// PDU populated the address — an extractIPFromIndex/Value miss for
	// legacy rows, or an unrecognized value for modern rows.
	if !fieldFound || ipAddress.Address == nil || *ipAddress.Address == "" {
		return nil
	}

	m.applyDefaults(&ipAddress, defaults)
	m.logger.Debug("successfully mapped IP address", "address", *ipAddress.Address)

	source := "legacy"
	if isInetAddress {
		source = "modern"
	}
	entityRegistry.MarkIPSource(&ipAddress, source)

	return &ipAddress
}

func derefAddr(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// lookupSiblingValue returns the .Value of the PDU whose OID matches
// the given OID with one column-substitution applied. Used by the
// addressPrefix handler to fetch the companion ipAddressIfIndex (.3)
// PDU value from the same ipAddressTable row. Empty string when no
// sibling PDU is present.
func lookupSiblingValue(values map[ObjectIDIndex]*ObjectIDValue, sourceOID, fromColumn, toColumn string) string {
	siblingOID := strings.Replace(sourceOID, fromColumn, toColumn, 1)
	if pdu, ok := values[ObjectIDIndex(siblingOID)]; ok && pdu != nil {
		return pdu.Value
	}
	return ""
}

// addressInsidePrefix returns true if (1) the encoded network bytes
// are already a valid prefix-table row index — i.e. all host bits are
// zero — and (2) the canonical IP address falls within that prefix.
//
// RFC 4293 specifies that ipAddressPrefixTable rows are indexed by
// the network address with host bits zeroed; a pointer carrying the
// host-bits-set form (e.g. addrBytes=10.0.0.1 with prefixLen=24
// instead of addrBytes=10.0.0.0) is structurally invalid even if the
// row's own address would fall inside the masked prefix. We treat
// such pointers as malformed and let the caller fall back to the
// host-route default.
func addressInsidePrefix(canonical string, networkBytes []byte, prefixLen int) bool {
	ip := net.ParseIP(canonical)
	if ip == nil {
		return false
	}
	var ipBytes []byte
	switch len(networkBytes) {
	case 4:
		v4 := ip.To4()
		if v4 == nil {
			return false
		}
		ipBytes = v4
	case 16:
		// To16() returns the 16-byte representation, but a v4-mapped
		// v6 like ::ffff:10.0.0.1 will then carry the same 16 bytes
		// as the embedded prefix encoding — exactly what we need to
		// compare against an addrType=2/addrLen=16 pointer.
		ipBytes = ip.To16()
		if ipBytes == nil {
			return false
		}
	default:
		return false
	}
	bits := len(networkBytes) * 8
	if prefixLen < 0 || prefixLen > bits {
		return false
	}
	mask := net.CIDRMask(prefixLen, bits)
	// (1) Reject pointers whose addrBytes still carry host bits.
	for i := range networkBytes {
		if networkBytes[i]&^mask[i] != 0 {
			return false
		}
	}
	// (2) Confirm the row's address falls within that prefix.
	for i := range networkBytes {
		if (ipBytes[i] & mask[i]) != networkBytes[i] {
			return false
		}
	}
	return true
}

// parseAddressPrefixRowPointer extracts the prefix length, family,
// pointed-to ifIndex, and network bytes from an ipAddressPrefix
// RowPointer value (.5 column of ipAddressTable).
//
// Expected shape (RFC 4293):
//
//	.1.3.6.1.2.1.4.32.1.5.<ifIndex>.<addrType>.<addrLen>.<addrBytes...>.<prefixLen>
//
// Per RFC 4293 the addrBytes are the prefix's network address — i.e.
// the row's address with the host bits zeroed. Callers can use the
// returned bytes to verify that the IP being mapped actually falls
// within the prefix described by the pointer; a pointer to an
// unrelated prefix row is treated as malformed. The returned ifIndex
// lets callers verify the prefix row belongs to the same interface
// as the source ipAddressTable row — without that check, a row could
// silently pick up another interface's prefix length when subnets
// overlap.
//
// Returns ok=false for:
//   - "0.0" / ".0.0" (zeroDotZero — RFC 4293 sentinel for "no prefix
//     row exists")
//   - any pointer that does not begin with .1.3.6.1.2.1.4.32.1.5
//   - the bare column OID with no row index appended
//   - empty / non-numeric tail
//   - addrType not in {1 (ipv4), 2 (ipv6)}, addrLen mismatch with the
//     declared family, or a byte-count that doesn't match addrLen.
//     Only structurally valid pointers are accepted; misshapen ones
//     fall back to the host-route default upstream rather than
//     silently producing a bogus prefix length.
func parseAddressPrefixRowPointer(pointer string) (prefixLen int, isV6 bool, ifIndex string, networkBytes []byte, ok bool) {
	if pointer == "" {
		return 0, false, "", nil, false
	}
	trimmed := strings.TrimPrefix(pointer, ".")
	if trimmed == "0.0" || trimmed == "" {
		return 0, false, "", nil, false
	}
	const prefixTablePrefix = "1.3.6.1.2.1.4.32.1.5"
	if !strings.HasPrefix(trimmed, prefixTablePrefix+".") {
		return 0, false, "", nil, false
	}
	suffix := trimmed[len(prefixTablePrefix)+1:]
	suffixParts := strings.Split(suffix, ".")
	// Layout positions: [0]=ifIndex, [1]=addrType, [2]=addrLen,
	// [3 .. 3+addrLen-1]=addrBytes, [last]=prefixLen.
	if len(suffixParts) < 4 {
		return 0, false, "", nil, false
	}
	// Validate ifIndex parses as a non-negative integer. We surface
	// the textual form so callers can compare it against the row's
	// own ipAddressIfIndex value, which is also a string.
	if iv, err := strconv.Atoi(suffixParts[0]); err != nil || iv < 0 {
		return 0, false, "", nil, false
	}
	addrType, err := strconv.Atoi(suffixParts[1])
	if err != nil {
		return 0, false, "", nil, false
	}
	addrLen, err := strconv.Atoi(suffixParts[2])
	if err != nil {
		return 0, false, "", nil, false
	}
	// Reject scoped (3=ipv4z, 4=ipv6z) and dns(16); their lengths are
	// not 4 or 16 and the spec already excludes them from the modern
	// ipAddressTable handling we support.
	var pointerIsV6 bool
	switch {
	case addrType == 1 && addrLen == 4:
		pointerIsV6 = false
	case addrType == 2 && addrLen == 16:
		pointerIsV6 = true
	default:
		return 0, false, "", nil, false
	}
	// Total expected sub-OIDs: 1 ifIndex + 1 addrType + 1 addrLen +
	// addrLen address bytes + 1 prefixLen.
	if len(suffixParts) != addrLen+4 {
		return 0, false, "", nil, false
	}
	tail := suffixParts[len(suffixParts)-1]
	n, err := strconv.Atoi(tail)
	if err != nil || n < 0 {
		return 0, false, "", nil, false
	}
	bytes := make([]byte, addrLen)
	for i := 0; i < addrLen; i++ {
		b, err := strconv.Atoi(suffixParts[3+i])
		if err != nil || b < 0 || b > 255 {
			return 0, false, "", nil, false
		}
		bytes[i] = byte(b)
	}
	return n, pointerIsV6, suffixParts[0], bytes, true
}

func maskToPrefixSize(maskStr string) (int, error) {
	parts := strings.Split(maskStr, ".")
	if len(parts) != 4 {
		return 0, fmt.Errorf("invalid mask format: %s", maskStr)
	}

	// Convert string to IP mask
	ip := net.ParseIP(maskStr)
	if ip == nil {
		return 0, fmt.Errorf("could not parse IP: %s", maskStr)
	}

	// Convert to 4-byte representation and compute prefix
	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("not an IPv4 address: %s", maskStr)
	}

	mask := net.IPv4Mask(ip[0], ip[1], ip[2], ip[3])
	ones, _ := mask.Size()

	return ones, nil
}

// ValidateIPv4CIDR validates an IPv4 address in CIDR notation (e.g., "192.168.1.1/24").
// Returns true if the format is valid, false otherwise. Used by the legacy
// ipAddrTable path; for tables that may carry IPv6 (RFC 4293 ipAddressTable)
// use ValidateIPCIDR instead.
func ValidateIPv4CIDR(cidr string) bool {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	// Verify it's IPv4 (not IPv6)
	if ip.To4() == nil {
		return false
	}

	// Verify prefix is in valid range (0-32 for IPv4)
	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones < 0 || ones > 32 {
		return false
	}

	return true
}

// ValidateIPCIDR validates an IPv4 or IPv6 address in CIDR notation
// (e.g., "192.168.1.1/24" or "2001:db8::1/64"). Used by the
// inet_address-indexed ipAddressTable path which produces both families.
func ValidateIPCIDR(cidr string) bool {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ip != nil
}

// InterfaceMapper is a struct that maps interfaces to entities
type InterfaceMapper struct {
	logger           *slog.Logger
	patternMatcher   *PatternMatcher
	userPatternCount int
	nameSource       string
}

// resolveInterfaceName selects Interface.Name from the two SNMP sources
// (both already trimSNMPString-sanitized) per the policy's
// interface_name_source. It returns "" only when both inputs are empty,
// so the caller's empty-name handling is preserved.
func resolveInterfaceName(source, ifDescr, ifName string) string {
	switch source {
	case config.InterfaceNameSourceIfName:
		if ifName != "" {
			return ifName
		}
		return ifDescr
	case config.InterfaceNameSourceIfDescr:
		if ifDescr != "" {
			return ifDescr
		}
		return ifName
	default: // auto (and any unrecognized value, defensively)
		// ifDescr preferred; ifName is promoted only when ifDescr is empty,
		// or ifDescr is a hardware description while ifName is not. This
		// reproduces the legacy inline name/name_alternate resolution —
		// including its treatment of DefaultInterfaceName as the unset
		// sentinel: a literal ifName of "unknown" is not promoted over a
		// descriptive ifDescr (the old code's currentClean guard excluded it).
		if ifDescr == "" {
			return ifName
		}
		if looksDescriptive(ifDescr) && ifName != "" &&
			ifName != DefaultInterfaceName && !looksDescriptive(ifName) {
			return ifName
		}
		return ifDescr
	}
}

// NewInterfaceMapper creates a new InterfaceMapper. nameSource is one of
// config.InterfaceNameSource{Auto,IfName,IfDescr}; an empty or unrecognized
// value is normalized to "auto". This normalization is a silent defensive
// belt — the user-facing warning for an unknown value is emitted once at
// policy parse (Manager.applyDefaults), because this constructor runs once
// per target per scrape.
func NewInterfaceMapper(logger *slog.Logger, patterns []config.InterfacePattern, nameSource string) (*InterfaceMapper, error) {
	switch nameSource {
	case config.InterfaceNameSourceIfName, config.InterfaceNameSourceIfDescr:
		// recognized; keep as-is
	default:
		// "auto", "", and any unrecognized value all resolve to auto.
		nameSource = config.InterfaceNameSourceAuto
	}

	var patternMatcher *PatternMatcher
	userPatternCount := len(patterns)

	// Always merge patterns to include built-in defaults
	mergedPatterns := MergePatterns(patterns, true)

	// Create pattern matcher if we have any patterns (user or built-in)
	if len(mergedPatterns) > 0 {
		var err error
		patternMatcher, err = NewPatternMatcher(mergedPatterns, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create pattern matcher: %w", err)
		}
	}

	return &InterfaceMapper{
		logger:           logger,
		patternMatcher:   patternMatcher,
		userPatternCount: userPatternCount,
		nameSource:       nameSource,
	}, nil
}

// applyDefaults applies default values to an interface entity
func (m *InterfaceMapper) applyDefaults(entity *diode.Interface, defaults *config.Defaults) {
	if defaults == nil {
		return
	}
	entityDefaults := defaults.Interface

	// Collect tags from both entity-specific and global defaults
	var tags []*diode.Tag
	if len(entityDefaults.Tags) > 0 {
		for _, tag := range entityDefaults.Tags {
			tags = append(tags, &diode.Tag{Name: &tag})
		}
	}
	if len(defaults.Tags) > 0 {
		for _, tag := range defaults.Tags {
			tags = append(tags, &diode.Tag{Name: &tag})
		}
	}

	// Apply tags if any exist
	if len(tags) > 0 {
		entity.Tags = tags
	}

	// Apply global defaults if not overridden by entity-specific defaults
	if entity.Description == nil && entityDefaults.Description != "" {
		entity.Description = &entityDefaults.Description
	}

	if entity.Type == nil || *entity.Type == "" {
		entity.Type = &entityDefaults.Type
	}
}

// Map maps interfaces to entities
func (m *InterfaceMapper) Map(values map[ObjectIDIndex]*ObjectIDValue, mappingEntry *Entry, entityRegistry *EntityRegistry, defaults *config.Defaults) diode.Entity {
	m.logger.Debug("mapping values to interface entity", "values", values, "mapping_entry", mappingEntry)
	interfaceEntity := entityRegistry.GetOrCreateEntity(InterfaceEntityType, getIndex(values)).(*diode.Interface)

	fieldFound := false
	var snmpIfType string            // Store SNMP ifType for final type resolution
	var ifDescrRaw, ifNameRaw string // ifDescr / ifName; Name resolved post-loop

	valueKeys := make([]ObjectIDIndex, 0, len(values))
	for objectID := range values {
		valueKeys = append(valueKeys, objectID)
	}
	// Sort the keys to ensure a consistent processing order.
	// Reverse the keys to prioritize fields like speed before type during mapping.
	slices.Sort(valueKeys)
	slices.Reverse(valueKeys)
	for _, objectID := range valueKeys {
		value := values[objectID]
		for _, propertyMappingEntry := range mappingEntry.MappingEntries {
			if objectID.HasParent(propertyMappingEntry.OID) {
				m.logger.Debug("mapping value to interface entity with mapper", "object_id", objectID, "value", value)
				switch propertyMappingEntry.Field {
				case "name":
					// Capture ifDescr; Interface.Name is resolved once after
					// the loop per interface_name_source (resolveInterfaceName).
					ifDescrRaw = trimSNMPString(value.Value)
				case "name_alternate":
					// Capture ifName (ifXTable); see resolveInterfaceName.
					ifNameRaw = trimSNMPString(value.Value)
				case "description":
					description := trimSNMPString(value.Value)
					if description != "" {
						if len(description) > 200 {
							description = description[:197] + "..."
						}
						interfaceEntity.Description = &description
						fieldFound = true
					}
				case "type":
					// Store SNMP ifType but defer type resolution until after all fields are processed
					// This ensures name and speed are available for pattern matching
					snmpIfType = value.Value
					fieldFound = true
				case "speed":
					if value.Value == "" {
						m.logger.Debug("speed is empty", "value", value.Value)
						continue
					}
					speed, err := strconv.Atoi(value.Value)
					if err != nil {
						m.logger.Warn("error converting speed to int", "error", err, "value", value.Value)
						continue
					}
					bitsPerSecond := int64(speed)
					kiloBitsPerSecond := bitsPerSecond / 1000
					// Check if speed is within valid range (0 to 2147483647 inclusive)
					if kiloBitsPerSecond < minInterfaceSpeed || kiloBitsPerSecond > maxInterfaceSpeed {
						m.logger.Warn("interface speed is outside valid range (0-2147483647)", "speed", speed, "value",
							value.Value, "mapping_id", propertyMappingEntry.OID, "interface_index", objectID)
						continue
					}
					if interfaceEntity.Speed != nil && *interfaceEntity.Speed > 0 {
						m.logger.Debug("interface speed already set, skipping", "existing_speed", *interfaceEntity.Speed,
							"new_speed", kiloBitsPerSecond, "interface_index", objectID)
						continue
					}
					interfaceEntity.Speed = &kiloBitsPerSecond
					fieldFound = true
				case "highSpeed":
					if value.Value == "" {
						m.logger.Debug("high_speed is empty", "value", value.Value)
						continue
					}
					highSpeed, err := strconv.Atoi(value.Value)
					if err != nil {
						m.logger.Warn("error converting high_speed to int", "error", err, "value", value.Value)
						continue
					}
					speedMbps := int64(highSpeed)
					// Check if highSpeed is within valid range (0 to 2147483647 inclusive)
					if speedMbps < minInterfaceSpeed || speedMbps > maxInterfaceSpeed {
						m.logger.Warn("interface high_speed is outside valid range (0-2147483647)", "highSpeed",
							highSpeed, "value", value.Value, "mapping_id", propertyMappingEntry.OID, "interface_index", objectID)
						continue
					}
					kiloBitsPerSecond := speedMbps * 1000
					interfaceEntity.Speed = &kiloBitsPerSecond
					fieldFound = true
				case "mtu":
					if value.Value == "" {
						m.logger.Debug("mtu is empty", "value", value.Value)
						continue
					}
					mtu, err := strconv.ParseInt(value.Value, 10, 64)
					if err != nil {
						m.logger.Warn("error converting mtu to int64", "error", err, "value", value.Value)
						continue
					}
					if mtu == 0 {
						m.logger.Debug("mtu is zero, skipping", "value", value.Value)
						continue
					}
					// Check if MTU is within valid range (1 to 2147483647 inclusive) and not overflowing int32
					if mtu < minInterfaceMTU || mtu > maxInterfaceMTU {
						m.logger.Warn("interface MTU is outside valid range (1-2147483647) or overflows int32", "mtu", mtu,
							"value", value.Value, "mapping_id", propertyMappingEntry.OID, "interface_index", objectID)
						continue
					}
					mtu64 := mtu
					interfaceEntity.Mtu = &mtu64
					fieldFound = true
				case "macAddress":
					macAddress, err := m.FormatMACAddress(value.Value)
					if err != nil {
						m.logger.Debug("error formatting mac address", "error", err, "value", value.Value)
						continue
					}
					interfaceEntity.PrimaryMacAddress = &diode.MACAddress{
						MacAddress: &macAddress, // TODO: This format is not correct - being rejected by netbox
					}
					fieldFound = true
				case "adminStatus":
					enabled := value.Value == "1"
					interfaceEntity.Enabled = &enabled
					fieldFound = true
				default:
					m.logger.Warn("unknown field", "field", propertyMappingEntry.Field)
				}
			}
		}
	}

	// Resolve Interface.Name from the two SNMP sources once, after the
	// property loop, so the choice is explicit and order-independent.
	// Done before type resolution below, which reads interfaceEntity.Name.
	if name := resolveInterfaceName(m.nameSource, ifDescrRaw, ifNameRaw); name != "" {
		interfaceEntity.Name = &name
		fieldFound = true
	}

	// Resolve interface type after all fields are collected
	// This ensures name and speed are available for pattern matching
	if snmpIfType != "" {
		var interfaceName string
		if interfaceEntity.Name != nil {
			interfaceName = *interfaceEntity.Name
		}

		defaultType := ""
		if defaults != nil && defaults.Interface.Type != "" {
			defaultType = defaults.Interface.Type
		}

		interfaceType := ResolveInterfaceType(
			interfaceName,
			snmpIfType,
			interfaceEntity.Speed,
			defaultType,
			m.patternMatcher,
			m.userPatternCount,
		)
		interfaceEntity.Type = &interfaceType
	}

	// Apply defaults if available
	if fieldFound {
		m.applyDefaults(interfaceEntity, defaults)
		if interfaceEntity.Name != nil {
			m.logger.Debug("successfully mapped interface", "name", *interfaceEntity.Name)
		} else {
			m.logger.Debug("successfully mapped interface (name field empty)")
		}
	}

	// Mark this interface as actually walked (regardless of whether
	// ifDescr/ifName populated the Name). Downstream code uses this
	// to distinguish a real ifTable row from the placeholder Interface
	// fabricated by GetOrCreateEntity when ipAddressIfIndex references
	// an ifIndex whose ifTable row was never walked.
	entityRegistry.MarkInterfaceVerified(interfaceEntity)

	return interfaceEntity
}

// FormatMACAddress formats a MAC address from a string to a colon-separated hex string
func (m *InterfaceMapper) FormatMACAddress(input string) (string, error) {
	// Decode the hex string to bytes
	bytes := []byte(input)

	// Check for correct MAC address length
	if len(bytes) != 6 {
		return "", fmt.Errorf("invalid MAC address length: got %d bytes", len(bytes))
	}

	// Check if MAC address is all zeros (00:00:00:00:00:00)
	allZeros := true
	for _, b := range bytes {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		return "", fmt.Errorf("invalid MAC address: 00:00:00:00:00:00 is not a valid hardware address")
	}

	// Format to colon-separated hex string
	var parts []string
	for _, b := range bytes {
		parts = append(parts, fmt.Sprintf("%02X", b))
	}

	output := strings.Join(parts, ":")
	m.logger.Debug("formatted mac address", "input", input, "output", output)
	return output, nil
}

// DeviceMapper is a struct that maps devices to entities
type DeviceMapper struct {
	manufacturers data.ManufacturerRetriever
	deviceLookup  data.DeviceRetriever
	logger        *slog.Logger
}

// applyDefaults applies default values to a device entity
func (m *DeviceMapper) applyDefaults(entity *diode.Device, defaults *config.Defaults, walked map[string]string) {
	if defaults == nil {
		return
	}
	entityDefaults := defaults.Device

	// Collect tags from both entity-specific and global defaults
	var tags []*diode.Tag
	if len(entityDefaults.Tags) > 0 {
		for _, tag := range entityDefaults.Tags {
			tags = append(tags, &diode.Tag{Name: &tag})
		}
	}
	if len(defaults.Tags) > 0 {
		for _, tag := range defaults.Tags {
			tags = append(tags, &diode.Tag{Name: &tag})
		}
	}

	// Apply tags if any exist
	if len(tags) > 0 {
		entity.Tags = tags
	}

	// Apply global defaults if not overridden by entity-specific defaults
	if entity.Description == nil && entityDefaults.Description != "" {
		entity.Description = &entityDefaults.Description
	}
	if entity.Comments == nil && entityDefaults.Comments != "" {
		entity.Comments = &entityDefaults.Comments
	}

	if entity.Role == nil && defaults.Role != "" {
		entity.Role = &diode.DeviceRole{
			Name: &defaults.Role,
		}
	}

	if entity.Site == nil && defaults.Site != "" {
		entity.Site = &diode.Site{
			Name: &defaults.Site,
		}
	}

	if defaults.Location != "" {
		if resolved, ok := data.ResolveDefault(defaults.Location, walked); ok {
			// Builds a fresh Location, overriding anything a future
			// mapper may have set on entity.Location. Site is taken from
			// defaults.Site only; a Site that was previously attached to
			// entity.Location is not preserved. No mapper sets
			// entity.Location today, so this is a documented forward
			// invariant rather than an observable change.
			loc := &diode.Location{Name: &resolved}
			if defaults.Site != "" {
				loc.Site = &diode.Site{Name: &defaults.Site}
			}
			entity.Location = loc
		}
	}

	if defaults.AssetTag != "" {
		if resolved, ok := data.ResolveDefault(defaults.AssetTag, walked); ok {
			if reason, ok := vetAssetTag(resolved); !ok {
				m.logger.Warn("defaults.asset_tag resolved value skipped: "+reason,
					"default", defaults.AssetTag)
			} else {
				entity.AssetTag = &resolved
			}
		}
	}
}

// CurrentDeviceIndex is the index of the current device
const CurrentDeviceIndex = "CURRENT"

// NewDeviceMapper creates a new DeviceMapper
func NewDeviceMapper(manufacturers data.ManufacturerRetriever, deviceLookup data.DeviceRetriever, logger *slog.Logger) *DeviceMapper {
	return &DeviceMapper{
		manufacturers: manufacturers,
		deviceLookup:  deviceLookup,
		logger:        logger,
	}
}

// Map maps devices to entities
func (m *DeviceMapper) Map(values map[ObjectIDIndex]*ObjectIDValue, mappingEntry *Entry, entityRegistry *EntityRegistry, defaults *config.Defaults) diode.Entity {
	m.logger.Debug("mapping values to device entity", "values", values, "mapping_entry", mappingEntry)
	deviceEntity := entityRegistry.GetOrCreateEntity(EntityType(mappingEntry.Entity), CurrentDeviceIndex).(*diode.Device)

	// Build the walked OID->value map once per Map() call so the
	// "platform" branch (and any future dynamic-ref consumer) reuses
	// the same snapshot instead of rebuilding it on every iteration.
	walked := make(map[string]string, len(values))
	for _, w := range values {
		walked[w.OID] = w.Value
	}

	fieldFound := false
	// Iterate values in sorted-OID order (ascending) instead of relying on
	// Go's randomized map iteration. Scalar fields (sysName etc.) are
	// unaffected by ordering; the sort exists so that any future table-valued
	// device field can apply "lowest-index non-empty wins" deterministically.
	valueKeys := make([]ObjectIDIndex, 0, len(values))
	for objectID := range values {
		valueKeys = append(valueKeys, objectID)
	}
	slices.SortFunc(valueKeys, compareOIDsNumerically)
	for _, objectID := range valueKeys {
		value := values[objectID]
		for _, propertyMappingEntry := range mappingEntry.MappingEntries {
			if objectID.HasParent(propertyMappingEntry.OID) {
				m.logger.Debug("mapping value to device entity with mapper", "object_id", objectID, "value", value, "mapping_entry", propertyMappingEntry)
				switch propertyMappingEntry.Field {
				case "name":
					name := trimSNMPString(value.Value)
					if name != "" {
						deviceEntity.Name = &name
						fieldFound = true
					}
				case "description":
					description := trimSNMPString(value.Value)
					if description != "" {
						if len(description) > 200 {
							description = description[:197] + "..."
						}
						deviceEntity.Description = &description
						fieldFound = true
					}
				case "platform":
					manufacturerID, err := m.getManufacturerID(value.Value)
					if err != nil {
						m.logger.Warn("error getting device IDs", "error", err, "value", value.Value)
						continue
					}
					manufacturer, err := m.manufacturers.GetManufacturer(manufacturerID)
					if err != nil {
						m.logger.Warn("error getting manufacturer", "error", err, "manufacturer_id", manufacturerID)
						manufacturer = value.Value
					}

					// Resolve the device model against the walked OID
					// snapshot built at the top of Map(). Dynamic
					// devices[] refs (e.g. MikroTik's shared sysObjectID
					// pointing at sysDescr) read from this snapshot
					// without any extra SNMP traffic — the MIB-II
					// system-group scalars sysObjectID and sysDescr
					// share ifIndex "0" under the device mapping's
					// identifier_size=1, so sysDescr IS present.
					deviceModel, err := m.deviceLookup.GetDeviceModel(value.Value, walked)
					if err != nil {
						m.logger.Warn("error getting device model falling back to OID", "error", err, "device_oid", value.Value)
						deviceModel = value.Value
					}

					// Apply per-target overrides (config.DeviceDefaults)
					// after auto-discovery so a policy author can hard-pin
					// any subset of {Model, Manufacturer, Platform}.
					// Order matters: apply Manufacturer first so a
					// Manufacturer-only override also flows into Platform.Name
					// (which defaults to the manufacturer string). An
					// explicit Platform override then wins over that.
					if defaults != nil && defaults.Device.Manufacturer != "" {
						manufacturer = defaults.Device.Manufacturer
					}
					platformName := manufacturer
					if defaults != nil && defaults.Device.Platform != "" {
						platformName = defaults.Device.Platform
					}
					if defaults != nil && defaults.Device.Model != "" {
						deviceModel = defaults.Device.Model
					}

					manufacturerEntity := diode.Manufacturer{
						Name: &manufacturer,
					}
					deviceEntity.Platform = &diode.Platform{
						Name:         &platformName,
						Slug:         toSlug(&platformName),
						Manufacturer: &manufacturerEntity,
					}
					deviceEntity.DeviceType = &diode.DeviceType{
						Model:        &deviceModel,
						Manufacturer: &manufacturerEntity,
					}
					fieldFound = true
				case "sysContact":
					// Walked solely so defaults can reference this OID;
					// no direct mapper consumption. Mark fieldFound so
					// applyDefaults still runs for devices that respond
					// to sysContact but not to name/description/platform.
					fieldFound = true
				case "sysLocation":
					// Walked solely so defaults can reference this OID;
					// no direct mapper consumption. Mark fieldFound so
					// applyDefaults still runs for devices that respond
					// to sysLocation but not to name/description/platform.
					fieldFound = true
				default:
					m.logger.Warn("unknown field", "field", propertyMappingEntry.Field)
				}
			}
		}
	}

	// Apply defaults if available
	if fieldFound {
		m.applyDefaults(deviceEntity, defaults, walked)
		if deviceEntity.Name != nil {
			m.logger.Debug("successfully mapped device", "name", *deviceEntity.Name)
		} else {
			m.logger.Debug("successfully mapped device (name field empty)")
		}
	}

	return deviceEntity
}

func (m *DeviceMapper) getManufacturerID(objectID string) (string, error) {
	parts := strings.Split(objectID, ".")
	if len(parts) > 0 && parts[0] == "" {
		parts = parts[1:]
	}

	const ManufacturerIDIndex = 6
	// Check if we have enough parts to extract manufacturer and model IDs
	if len(parts) > ManufacturerIDIndex {
		return parts[ManufacturerIDIndex], nil
	}

	return "", fmt.Errorf("invalid objectID: %s", objectID)
}

func toSlug(input *string) *string {
	// Convert to lowercase
	slug := strings.ToLower(*input)

	// Remove all non-word characters (except spaces and dashes)
	re := regexp.MustCompile(`[^\w\s-]`)
	slug = re.ReplaceAllString(slug, "")

	// Replace spaces and underscores with dashes
	slug = strings.ReplaceAll(slug, " ", "-")
	slug = strings.ReplaceAll(slug, "_", "-")

	// Collapse multiple dashes into one
	re = regexp.MustCompile(`-+`)
	slug = re.ReplaceAllString(slug, "-")

	// Trim leading/trailing dashes
	slug = strings.Trim(slug, "-")

	return &slug
}

// compareOIDsNumerically compares two OID strings by their numeric components,
// not lexicographically. This ensures .11.2 sorts before .11.10.
func compareOIDsNumerically(a, b ObjectIDIndex) int {
	partsA := strings.Split(strings.Trim(string(a), "."), ".")
	partsB := strings.Split(strings.Trim(string(b), "."), ".")
	for i := 0; i < len(partsA) && i < len(partsB); i++ {
		na, errA := strconv.Atoi(partsA[i])
		nb, errB := strconv.Atoi(partsB[i])
		if errA != nil || errB != nil {
			// Fall back to string comparison for non-numeric components
			if partsA[i] != partsB[i] {
				if partsA[i] < partsB[i] {
					return -1
				}
				return 1
			}
			continue
		}
		if na != nb {
			return na - nb
		}
	}
	return len(partsA) - len(partsB)
}
