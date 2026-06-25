package mapping

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
)

// listKeyAndLeaf splits an absolute path into the list key and the remaining
// leaf path, relative to listPath. Returns ok=false when path is not under
// listPath. e.g. (/interfaces/interface[name=Eth1]/state/mtu, /interfaces/interface)
// -> ("Eth1", "state/mtu", true).
func listKeyAndLeaf(path, listPath string) (key, leaf string, ok bool) {
	prefix := listPath + "["
	if !strings.HasPrefix(path, prefix) {
		return "", "", false
	}
	rest := path[len(prefix):]
	closeBracket := strings.Index(rest, "]")
	if closeBracket < 0 {
		return "", "", false
	}
	kv := rest[:closeBracket] // e.g. name=Eth1
	eq := strings.Index(kv, "=")
	if eq < 0 {
		return "", "", false
	}
	key = kv[eq+1:]
	leaf = strings.TrimPrefix(rest[closeBracket+1:], "/")
	return key, leaf, true
}

func strptr(s string) *string { return &s }

func toInt64Ptr(v any) *int64 {
	switch n := v.(type) {
	case int:
		x := int64(n)
		return &x
	case int64:
		return &n
	case uint:
		if uint64(n) > math.MaxInt64 { // uint is 64-bit on 64-bit platforms
			return nil
		}
		x := int64(n)
		return &x
	case uint8:
		x := int64(n)
		return &x
	case uint16:
		x := int64(n)
		return &x
	case uint32:
		x := int64(n)
		return &x
	case uint64:
		if n > math.MaxInt64 {
			return nil
		}
		x := int64(n)
		return &x
	case float64:
		// Guard before converting: an out-of-range float -> int64 is
		// implementation-defined in Go, so a malformed decoded value could become a
		// surprising (possibly negative) result. Reject NaN/Inf/out-of-range.
		if math.IsNaN(n) || math.IsInf(n, 0) || n < math.MinInt64 || n > math.MaxInt64 {
			return nil
		}
		x := int64(n)
		return &x
	case string:
		if x, err := strconv.ParseInt(n, 10, 64); err == nil {
			return &x
		}
	}
	return nil
}

func toStr(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func sortStrings(s []string) { sort.Strings(s) }

// identityRefBase normalizes a YANG identityref value: it strips any module
// prefix, trims surrounding whitespace, and upper-cases the result. JSON_IETF
// serializes identityrefs as "module:VALUE" (e.g. "openconfig-platform-types:CHASSIS"
// or "iana-if-type:ieee8023adLag"); a bare "VALUE" also occurs. Both normalize to
// the upper-cased base ("CHASSIS", "IEEE8023ADLAG").
func identityRefBase(v any) string {
	t := toStr(v)
	if i := strings.LastIndex(t, ":"); i >= 0 {
		t = t[i+1:]
	}
	return strings.ToUpper(strings.TrimSpace(t))
}

// componentType returns the component's OpenConfig type as a normalized
// identityref base (see identityRefBase).
func componentType(typeVal any) string {
	return identityRefBase(typeVal)
}

// ocInterfaceTypeToNetBox maps a normalized OpenConfig interface-type identityref
// (UPPER, prefix-stripped; see identityRefBase) to a NetBox interface type. It
// covers the structural types derivable from the OC type alone — lag and the
// virtual families. ethernetCsmacd / IF_ETHERNET are intentionally absent: media
// (speed/connector) is unknown from the OC type, so an ethernet interface falls
// through to a user interface_patterns rule or the interface.if_type default.
var ocInterfaceTypeToNetBox = map[string]string{
	"IEEE8023ADLAG":    "lag",
	"IF_AGGREGATE":     "lag",
	"SOFTWARELOOPBACK": "virtual",
	"IF_LOOPBACK":      "virtual",
	"L2VLAN":           "virtual",
	"L3IPVLAN":         "virtual",
	"PROPVIRTUAL":      "virtual",
	"TUNNEL":           "virtual",
}

// firstNonEmpty returns the first argument that is non-empty after trimming
// surrounding whitespace, returning that trimmed value, or "" if all are
// empty/whitespace. Used for the manufacturer/model precedence chains (policy
// default overrides discovered, discovered overrides "Unknown"); trimming keeps
// a whitespace-only leaf from winning and producing a Manufacturer/Model named " ".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// filterNonEmpty returns the non-empty arguments in order, used to compose the
// Platform name from the operator's NOS-name prefix and the discovered version.
func filterNonEmpty(vals ...string) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// componentsByKey groups the /components/component leaves in snap by their list
// key, returning the per-key leaf maps and the sorted key order. Shared by
// translateDevice (chassis serial) and translateComponents (modules) so the
// grouping logic exists in exactly one place. Returns nil order when the
// profile has no components list_path.
func componentsByKey(profile *Profile, snap map[string]any) (map[string]map[string]any, []string) {
	listPath := profile.Components.ListPath
	if listPath == "" {
		return nil, nil
	}
	byKey := map[string]map[string]any{}
	var order []string
	for path, val := range snap {
		key, leaf, ok := listKeyAndLeaf(path, listPath)
		if !ok {
			continue
		}
		if _, seen := byKey[key]; !seen {
			byKey[key] = map[string]any{}
			order = append(order, key)
		}
		byKey[key][leaf] = val
	}
	sortStrings(order)
	return byKey, order
}

// toTags converts tag names to Diode Tag refs, de-duplicating. It always
// operates on a fresh clone so callers' slices are never mutated.
func toTags(names []string) []*diode.Tag {
	if len(names) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]*diode.Tag, 0, len(names))
	for _, n := range names {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, &diode.Tag{Name: strptr(n)})
	}
	return out
}

// Translate converts a reconciled snapshot into Diode entities using profile.
// It always emits one *diode.Device, then interfaces, then components
// (ModuleBay before its Module, mirroring snmp-discovery ordering).
func Translate(profile *Profile, snap map[string]any, defaults *config.Defaults, discoveredVendor string) []diode.Entity {
	dev, deviceMfg := translateDevice(profile, snap, defaults, discoveredVendor)
	entities := []diode.Entity{dev}
	ifaceEntities := translateInterfaces(profile, snap, dev, defaults)
	entities = append(entities, ifaceEntities...)
	entities = append(entities, translateComponents(profile, snap, dev, deviceMfg)...)
	entities = append(entities, translateIPs(profile, snap, dev, defaults, compileInterfaceExcludes(defaults))...) // Device -> Interfaces -> Modules -> subifs+IPs
	// VLANs: build definitions (real names/status) + the shared builder, attach
	// switchport membership, then force-emit every defined VLAN (even unreferenced).
	vlanDefs := translateVlanDefinitions(snap)
	vb := newVlanBuilder(dev, defaults, vlanDefs)
	ifacesByName := map[string]*diode.Interface{}
	for _, e := range ifaceEntities {
		if i, ok := e.(*diode.Interface); ok && i.Name != nil {
			ifacesByName[*i.Name] = i
		}
	}
	translateSwitchports(profile, snap, vb, ifacesByName)
	for vid := range vlanDefs {
		vb.get(vid) // ensure defined-but-unreferenced VLANs are emitted
	}
	entities = append(entities, vb.emitted()...)
	// VRFs: emit L3VRF network-instances and bind Vrf on member interfaces (and
	// their IPs), subinterface-precise via the interface-entity name.
	vrfEntities, vrfByIface := translateVrfs(snap, defaults)
	if len(vrfByIface) > 0 {
		for _, e := range entities {
			switch v := e.(type) {
			case *diode.Interface:
				if v.Name != nil {
					if vrf := vrfByIface[*v.Name]; vrf != nil {
						v.Vrf = vrf
					}
				}
			case *diode.IPAddress:
				if iface, ok := v.AssignedObject.(*diode.Interface); ok && iface != nil && iface.Name != nil {
					if vrf := vrfByIface[*iface.Name]; vrf != nil {
						v.Vrf = vrf
					}
				}
			}
		}
	}
	entities = append(entities, vrfEntities...)
	// Prefixes: derive the connected network of each discovered IP (VRF inherited
	// from the IP, scoped to the device site). Must run after the VRF post-pass so
	// IPAddress.Vrf is set.
	entities = append(entities, translatePrefixes(entities, dev, defaults)...)
	return entities
}

// translateDevice builds the Device entity and returns the resolved device
// manufacturer so translateComponents can fall back to it for modules that do
// not report their own mfg-name.
//
// Manufacturer precedence (policy default overrides discovered, mirroring the
// repo convention): defaults.Device.Manufacturer > chassis mfg-name >
// Capabilities vendor > "Unknown". Model precedence: defaults.Device.Model >
// chassis part-no > "Unknown".
func translateDevice(profile *Profile, snap map[string]any, defaults *config.Defaults, discoveredVendor string) (*diode.Device, string) {
	dev := &diode.Device{}
	if profile.Device.Hostname != "" {
		if v, ok := snap[profile.Device.Hostname]; ok {
			dev.Name = strptr(toStr(v))
		}
	}

	// Resolve the device manufacturer/model from the CHASSIS component leaves and
	// the gNMI Capabilities vendor, with the policy default taking precedence.
	var chassisMfg, chassisPart string
	mfgLeaf := profile.Components.Keys["mfg_name"]
	partLeaf := profile.Components.Keys["part"]
	typeLeaf := profile.Components.Keys["type"]
	if typeLeaf != "" {
		byKey, order := componentsByKey(profile, snap)
		for _, key := range order {
			leaves := byKey[key]
			if componentType(leaves[typeLeaf]) != "CHASSIS" {
				continue
			}
			if mfgLeaf != "" {
				chassisMfg = toStr(leaves[mfgLeaf])
			}
			if partLeaf != "" {
				chassisPart = toStr(leaves[partLeaf])
			}
			break
		}
	}
	var defaultMfg, defaultModel string
	if defaults != nil {
		defaultMfg = defaults.Device.Manufacturer
		defaultModel = defaults.Device.Model
	}
	deviceMfg := firstNonEmpty(defaultMfg, chassisMfg, discoveredVendor, "Unknown")
	deviceModel := firstNonEmpty(defaultModel, chassisPart, "Unknown")

	// NetBox requires device_type with both manufacturer and model, so DeviceType
	// is ALWAYS emitted. With discovery these are real values; "Unknown" is only a
	// last resort when neither a default nor a discovered value is present.
	dev.DeviceType = &diode.DeviceType{
		Model:        strptr(deviceModel),
		Manufacturer: &diode.Manufacturer{Name: strptr(deviceMfg)},
	}

	if defaults != nil {
		if defaults.Site != "" {
			dev.Site = &diode.Site{Name: strptr(defaults.Site)}
		}
		if defaults.Role != "" {
			dev.Role = &diode.DeviceRole{Name: strptr(defaults.Role)}
		}
		// Platform name folds the discovered software version into the operator's
		// platform default (treated as the NOS-name prefix), mirroring the
		// device-discovery convention (no Diode custom fields). e.g. "Arista EOS"
		// + "4.30.1F" -> "Arista EOS 4.30.1F". Set only when at least one of the
		// default prefix or the discovered version is present, so the prior
		// default-only behavior is preserved.
		var osVersion string
		if profile.Device.OSVersion != "" {
			if v, ok := snap[profile.Device.OSVersion]; ok {
				osVersion = toStr(v)
			}
		}
		platformName := strings.TrimSpace(strings.Join(filterNonEmpty(defaults.Device.Platform, osVersion), " "))
		if platformName != "" {
			// Platform carries the resolved device manufacturer (discovered or
			// default), not just the default, so the platform's manufacturer matches
			// the DeviceType's.
			dev.Platform = &diode.Platform{
				Name:         strptr(platformName),
				Manufacturer: &diode.Manufacturer{Name: strptr(deviceMfg)},
			}
		}
		if defaults.Location != "" {
			// Location is scoped to the device's Site (NetBox requires a site).
			dev.Location = &diode.Location{Name: strptr(defaults.Location), Site: dev.Site}
		}
		if defaults.Device.Comments != "" {
			dev.Comments = strptr(defaults.Device.Comments)
		}
		// asset_tag is resolved by the runner post-Translate (it may require a
		// targeted Get for a path reference, which needs the session) — see
		// mapping.ResolveAssetTag and runner.flush.
		// Device tags = policy-level tags + device-level tags, de-duped clone.
		if tags := toTags(append(append([]string{}, defaults.Tags...), defaults.Device.Tags...)); len(tags) > 0 {
			dev.Tags = tags
		}
	}
	// Status mirrors device-discovery's unconditional "active": gNMI reached the
	// device, so it is operationally present.
	dev.Status = strptr("active")
	// Device.Serial is taken from the CHASSIS component (the device's own
	// serial). CHASSIS is not an emittable component type, so translateComponents
	// skips it and there is no Module/Device serial conflict.
	if serial := chassisSerial(profile, snap); serial != "" {
		dev.Serial = strptr(serial)
	}
	return dev, deviceMfg
}

// chassisSerial returns the serial-no of the component whose type is CHASSIS, or
// "" when there is no such component (or it carries no serial).
func chassisSerial(profile *Profile, snap map[string]any) string {
	typeLeaf := profile.Components.Keys["type"]
	serialLeaf := profile.Components.Keys["serial"]
	if typeLeaf == "" || serialLeaf == "" {
		return ""
	}
	byKey, order := componentsByKey(profile, snap)
	for _, key := range order {
		leaves := byKey[key]
		if componentType(leaves[typeLeaf]) == "CHASSIS" {
			return toStr(leaves[serialLeaf])
		}
	}
	return ""
}

// compileInterfaceExcludes compiles defaults.InterfaceExcludePatterns into regexps
// (validated at policy parse; an unexpected compile error here skips the offending
// pattern). Shared by translateInterfaces and translateIPs so an excluded interface
// is suppressed for BOTH its own entity AND its addresses/derived prefixes.
func compileInterfaceExcludes(defaults *config.Defaults) []*regexp.Regexp {
	if defaults == nil {
		return nil
	}
	out := make([]*regexp.Regexp, 0, len(defaults.InterfaceExcludePatterns))
	for _, m := range defaults.InterfaceExcludePatterns {
		if re, err := regexp.Compile(m); err == nil {
			out = append(out, re)
		}
	}
	return out
}

// nameExcluded reports whether name matches any compiled exclude pattern.
func nameExcluded(name string, excludes []*regexp.Regexp) bool {
	for _, re := range excludes {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

func translateInterfaces(profile *Profile, snap map[string]any, dev *diode.Device, defaults *config.Defaults) []diode.Entity {
	listPath := profile.Interfaces.ListPath
	if listPath == "" {
		return nil
	}
	// group leaf values by interface key
	byKey := map[string]map[string]any{}
	var order []string
	for path, val := range snap {
		key, leaf, ok := listKeyAndLeaf(path, listPath)
		if !ok {
			continue
		}
		if _, seen := byKey[key]; !seen {
			byKey[key] = map[string]any{}
			order = append(order, key)
		}
		byKey[key][leaf] = val
	}
	sortStrings(order)

	defaultType := "other"
	var ifDefaultDesc string
	var ifTags []*diode.Tag
	var userPatterns []config.InterfacePattern
	if defaults != nil {
		if defaults.Interface.Type != "" {
			defaultType = defaults.Interface.Type
		}
		ifDefaultDesc = defaults.Interface.Description
		// Interface tags = policy-level tags + interface-level tags (defaults.tags
		// applies to all entities, mirroring the Device path).
		ifTags = toTags(append(append([]string{}, defaults.Tags...), defaults.Interface.Tags...))
		userPatterns = defaults.InterfacePatterns
	}
	// Compile the name patterns once per call. They were validated at policy
	// parse (manager.validatePolicy), so any compile error here is unexpected;
	// defensively skip the offending pattern rather than panicking. Per-flush
	// compilation is acceptable at inventory cadence (sample/get intervals are
	// minutes, on_change is debounced).
	compiledExcludes := compileInterfaceExcludes(defaults)
	compiledPatterns := make([]compiledIfacePattern, 0, len(userPatterns))
	for _, p := range userPatterns {
		if re, err := regexp.Compile(p.Match); err == nil {
			compiledPatterns = append(compiledPatterns, compiledIfacePattern{re: re, typ: p.Type})
		}
	}
	typeLeafPath := profile.Interfaces.Keys["type"]
	speedLeafPath := profile.Interfaces.Keys["speed"]
	macLeafPath := profile.Interfaces.Keys["mac_address"]
	lagLeafPath := profile.Interfaces.Keys["lag_member"]
	duplexLeafPath := profile.Interfaces.Keys["duplex"]

	var out []diode.Entity
	for _, key := range order {
		leaves := byKey[key]
		// 1) exclude patterns (regex on name) -> skip the interface entirely.
		if nameExcluded(key, compiledExcludes) {
			continue
		}
		// Resolve the interface type by precedence: user pattern (first match) ->
		// OpenConfig state/type map -> built-in name patterns -> speed-based media
		// inference -> policy default -> "other". See resolveInterfaceType.
		ocTypeBase := ""
		if typeLeafPath != "" {
			ocTypeBase = identityRefBase(leaves[typeLeafPath])
		}
		speedEnum := ""
		if speedLeafPath != "" {
			speedEnum = identityRefBase(leaves[speedLeafPath])
		}
		resolvedType := resolveInterfaceType(key, ocTypeBase, speedEnum, defaultType, compiledPatterns)
		iface := &diode.Interface{
			Device: dev,
			Name:   strptr(key),
			Type:   strptr(resolvedType),
		}
		if len(ifTags) > 0 {
			iface.Tags = ifTags
		}
		if leafPath := profile.Interfaces.Keys["description"]; leafPath != "" {
			if v, ok := leaves[leafPath]; ok {
				iface.Description = strptr(toStr(v))
			}
		}
		// Fall back to the policy's default interface description when the device
		// did not report one.
		if (iface.Description == nil || *iface.Description == "") && ifDefaultDesc != "" {
			iface.Description = strptr(ifDefaultDesc)
		}
		if leafPath := profile.Interfaces.Keys["admin_status"]; leafPath != "" {
			if v, ok := leaves[leafPath]; ok {
				enabled := strings.EqualFold(toStr(v), "UP")
				iface.Enabled = &enabled
			}
		}
		if leafPath := profile.Interfaces.Keys["mtu"]; leafPath != "" {
			if v, ok := leaves[leafPath]; ok {
				iface.Mtu = toInt64Ptr(v)
			}
		}
		if speedLeafPath != "" {
			if kbps, ok := ocSpeedToKbps[speedEnum]; ok {
				iface.Speed = &kbps
			}
		}
		if macLeafPath != "" {
			if v, ok := leaves[macLeafPath]; ok {
				if mac := normalizeMAC(toStr(v)); mac != "" {
					iface.PrimaryMacAddress = &diode.MACAddress{MacAddress: strptr(mac)}
				}
			}
		}
		if lagLeafPath != "" {
			if v, ok := leaves[lagLeafPath]; ok {
				// Skip a self-referential aggregate-id (agg == own name): the LAG
				// aggregate interface carries no aggregate-id under OC semantics, so
				// this only guards against a malformed target and avoids a self-LAG edge.
				if agg := strings.TrimSpace(toStr(v)); agg != "" && agg != key {
					iface.Lag = &diode.Interface{Device: dev, Name: strptr(agg)}
				}
			}
		}
		if duplexLeafPath != "" {
			if d, ok := ocDuplex[identityRefBase(leaves[duplexLeafPath])]; ok {
				iface.Duplex = strptr(d)
			}
		}
		out = append(out, iface)
	}
	return out
}

// emittableComponentTypes are OpenConfig component types we surface as Modules
// in the MVP. PSU/FAN/SENSOR are classified but not emitted (spec §2).
var emittableComponentTypes = map[string]bool{
	"LINECARD":    true,
	"MODULE":      true,
	"SUPERVISOR":  true,
	"FABRIC":      true,
	"TRANSCEIVER": true,
}

// translateComponents emits, per inventory-bearing component, a standalone
// ModuleBay entity FOLLOWED BY its Module. This mirrors snmp-discovery's
// ordering (Device -> ModuleBay -> Module) so Diode creates the module bay
// before the module that references it. The ModuleType always carries a
// Manufacturer (the component's own mfg-name, else the resolved device
// manufacturer, else "Unknown"), never model-only.
func translateComponents(profile *Profile, snap map[string]any, dev *diode.Device, deviceMfg string) []diode.Entity {
	if profile.Components.ListPath == "" {
		return nil
	}
	byKey, order := componentsByKey(profile, snap)

	typeLeaf := profile.Components.Keys["type"]
	serialLeaf := profile.Components.Keys["serial"]
	partLeaf := profile.Components.Keys["part"]
	mfgLeaf := profile.Components.Keys["mfg_name"]

	var out []diode.Entity
	for _, key := range order {
		leaves := byKey[key]
		ctype := componentType(leaves[typeLeaf])
		if !emittableComponentTypes[ctype] {
			continue
		}
		// 1) standalone ModuleBay, emitted first
		bay := &diode.ModuleBay{Device: dev, Name: strptr(key)}
		out = append(out, bay)

		// 2) Module referencing the bay, with a manufacturer-bearing ModuleType.
		// The module manufacturer is the component's own mfg-name (a module may be
		// from a different vendor than the chassis — e.g. a transceiver), falling
		// back to the resolved device manufacturer, then "Unknown".
		model := "Unknown"
		if partLeaf != "" {
			if v, ok := leaves[partLeaf]; ok && toStr(v) != "" {
				model = toStr(v)
			}
		}
		var componentMfgName string
		if mfgLeaf != "" {
			componentMfgName = toStr(leaves[mfgLeaf])
		}
		mfg := firstNonEmpty(componentMfgName, deviceMfg, "Unknown")
		mod := &diode.Module{
			Device:    dev,
			ModuleBay: bay,
			ModuleType: &diode.ModuleType{
				Model:        strptr(model),
				Manufacturer: &diode.Manufacturer{Name: strptr(mfg)},
			},
		}
		if serialLeaf != "" {
			if v, ok := leaves[serialLeaf]; ok {
				mod.Serial = strptr(toStr(v))
			}
		}
		out = append(out, mod)
	}
	return out
}
