package mapping

import (
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
)

// firstKeyVal expects s to start with "[<key>=<val>]" and returns val plus the
// remainder after the closing "]". Splitting on "]" (not "/") keeps values that
// contain "/" (e.g. Eth1/1) or ":" (IPv6) intact.
func firstKeyVal(s string) (val, rest string, ok bool) {
	if len(s) == 0 || s[0] != '[' {
		return "", "", false
	}
	c := strings.Index(s, "]")
	if c < 0 {
		return "", "", false
	}
	kv := s[1:c] // e.g. name=Ethernet1
	eq := strings.Index(kv, "=")
	if eq < 0 {
		return "", "", false
	}
	return kv[eq+1:], s[c+1:], true
}

// parseIPAddressPath extracts (iface, index, family, ip, leaf) from an
// OpenConfig subinterface IP path under ifaceListPath. family is "ipv4"/"ipv6";
// leaf is the path after the address key (we consume "state/prefix-length").
// Returns ok=false for any path not under the IP subtree.
func parseIPAddressPath(path, ifaceListPath string) (iface, index, family, ip, leaf string, ok bool) {
	if ifaceListPath == "" || !strings.HasPrefix(path, ifaceListPath+"[") {
		return
	}
	rest := path[len(ifaceListPath):] // "[name=Ethernet1]/subinterfaces/..."
	iface, rest, ok = firstKeyVal(rest)
	if !ok {
		return "", "", "", "", "", false
	}
	const sub = "/subinterfaces/subinterface"
	if !strings.HasPrefix(rest, sub) {
		return "", "", "", "", "", false
	}
	rest = rest[len(sub):]
	index, rest, ok = firstKeyVal(rest)
	if !ok {
		return "", "", "", "", "", false
	}
	switch {
	case strings.HasPrefix(rest, "/ipv4/"):
		family, rest = "ipv4", rest[len("/ipv4"):]
	case strings.HasPrefix(rest, "/ipv6/"):
		family, rest = "ipv6", rest[len("/ipv6"):]
	default:
		return "", "", "", "", "", false
	}
	const addr = "/addresses/address"
	if !strings.HasPrefix(rest, addr) {
		return "", "", "", "", "", false
	}
	rest = rest[len(addr):]
	ip, rest, ok = firstKeyVal(rest)
	if !ok {
		return "", "", "", "", "", false
	}
	leaf = strings.TrimPrefix(rest, "/")
	return iface, index, family, ip, leaf, true
}

// translateIPs emits an IPAddress per (interface, subinterface index, family, ip)
// that reports a prefix-length. index 0 assigns to the parent interface; index>0
// emits a child virtual subinterface "<iface>.<index>" (once) and assigns there.
func translateIPs(profile *Profile, snap map[string]any, dev *diode.Device, defaults *config.Defaults, excludes []*regexp.Regexp) []diode.Entity {
	listPath := profile.Interfaces.ListPath
	if listPath == "" {
		return nil
	}
	// Per-policy IPAddress defaults, computed once (identical for every address).
	var ipRole, ipDesc, ipComments *string
	var ipTenant *diode.Tenant
	var ipTags []*diode.Tag
	if defaults != nil {
		d := defaults.IPAddress
		if d.Role != "" {
			ipRole = strptr(d.Role)
		}
		if d.Tenant != "" {
			ipTenant = &diode.Tenant{Name: strptr(d.Tenant)}
		}
		if d.Description != "" {
			ipDesc = strptr(d.Description)
		}
		if d.Comments != "" {
			ipComments = strptr(d.Comments)
		}
		// IP tags = policy-level tags + ip_address-level tags, de-duped clone.
		ipTags = toTags(append(append([]string{}, defaults.Tags...), d.Tags...))
	}
	type addrKey struct{ iface, index, family, ip string }
	prefixLen := map[addrKey]string{}
	var order []addrKey
	for path, val := range snap {
		iface, index, family, ip, leaf, ok := parseIPAddressPath(path, listPath)
		if !ok || leaf != "state/prefix-length" {
			continue
		}
		// An interface excluded via interface_exclude_patterns is skipped entirely:
		// drop its addresses here too so they (and their derived prefixes) are not
		// ingested via a stub interface.
		if nameExcluded(iface, excludes) {
			continue
		}
		k := addrKey{iface, index, family, ip}
		if _, seen := prefixLen[k]; !seen {
			order = append(order, k)
		}
		prefixLen[k] = toStr(val)
	}
	sort.Slice(order, func(i, j int) bool {
		a, b := order[i], order[j]
		if a.iface != b.iface {
			return a.iface < b.iface
		}
		if a.index != b.index {
			return a.index < b.index
		}
		if a.family != b.family {
			return a.family < b.family
		}
		return a.ip < b.ip
	})

	children := map[string]*diode.Interface{} // "<iface>.<index>" -> emitted child
	var out []diode.Entity
	for _, k := range order {
		pl := prefixLen[k]
		if pl == "" {
			continue // skip addresses with no prefix-length (do not guess /32 or /128)
		}
		var assigned *diode.Interface
		if k.index == "0" {
			assigned = &diode.Interface{Device: dev, Name: strptr(k.iface)}
		} else {
			name := k.iface + "." + k.index
			ch, ok := children[name]
			if !ok {
				ch = &diode.Interface{
					Device: dev,
					Name:   strptr(name),
					Type:   strptr("virtual"),
					Parent: &diode.Interface{Device: dev, Name: strptr(k.iface)},
				}
				children[name] = ch
				out = append(out, ch) // emit the child subinterface before its IP
			}
			assigned = ch
		}
		ip := &diode.IPAddress{
			Address:        strptr(k.ip + "/" + pl),
			Status:         strptr("active"),
			AssignedObject: assigned,
			Role:           ipRole,
			Tenant:         ipTenant,
			Description:    ipDesc,
			Comments:       ipComments,
		}
		if len(ipTags) > 0 {
			ip.Tags = ipTags
		}
		out = append(out, ip)
	}
	return out
}

// AssignPrimaryIP sets Device.PrimaryIp4/6 to the emitted IPAddress whose bare
// address equals hostIP — the address the collector connected to is the device's
// primary management IP (mirrors device-discovery). Exact match only; never
// guesses. hostIP must already be stripped of any :port (the runner does this).
//
// It returns the LIVE matched *diode.IPAddress (still present in the entities
// slice — NOT the detached snapshot attached to the Device), so the caller can
// pass it to PruneNestedRefs as the cycle-closer identified by pointer identity:
// that single top-level ipam.ipaddress is the only entity allowed to set
// device.primary_ip4 on its nested device stub (diode reconciler bug #545).
// Returns nil on the empty / no-device / no-match paths.
//
// The primary IP RETAINS its assigned interface (via detachForPrimaryIP) because
// NetBox rejects a device primary IP that is not assigned to an interface on the
// device ("The specified IP address … is not assigned to this device"). The
// Device -> IPAddress -> Interface -> Device reference cycle is broken inside
// detachForPrimaryIP by pointing the assigned interface at a Device copy with
// PrimaryIp4/6 cleared and its relationship pointers stripped — matching
// snmp-discovery's detachForPrimaryIP. The rich IPAddress and Interface still
// ride as top-level entities; only this embedded snapshot is pruned.
func AssignPrimaryIP(entities []diode.Entity, hostIP string) *diode.IPAddress {
	if hostIP == "" || len(entities) == 0 {
		return nil
	}
	// Canonicalize the target so differing IPv6 spellings still match (e.g. a
	// policy host 2001:0db8::1 vs a discovered 2001:db8::1). targetIP is nil when
	// hostIP is not an IP literal, in which case we fall back to string equality.
	targetIP := net.ParseIP(hostIP)
	dev, _ := entities[0].(*diode.Device)
	if dev == nil {
		return nil
	}
	for _, e := range entities {
		ip, ok := e.(*diode.IPAddress)
		if !ok || ip.Address == nil {
			continue
		}
		bare := *ip.Address
		if i := strings.IndexByte(bare, '/'); i >= 0 {
			bare = bare[:i]
		}
		matched := bare == hostIP
		if bareIP := net.ParseIP(bare); bareIP != nil && targetIP != nil {
			matched = targetIP.Equal(bareIP) // canonical comparison
		}
		if !matched {
			continue
		}
		if strings.Contains(bare, ":") {
			dev.PrimaryIp6 = detachForPrimaryIP(ip, dev)
		} else {
			dev.PrimaryIp4 = detachForPrimaryIP(ip, dev)
		}
		return ip // the LIVE matched IPAddress (cycle-closer for PruneNestedRefs)
	}
	return nil
}

// detachForPrimaryIP returns a copy of the matched IPAddress suitable to attach
// as Device.PrimaryIp4/6 without a reference cycle, while preserving the
// assigned-interface link NetBox requires. The assigned Interface is copied with
// its Device replaced by a copy of the owning Device that has PrimaryIp4/6
// cleared, and its relationship pointers (Parent/Bridge/Lag/Module) stripped, so
// nothing transitively reaches a Device that still carries a primary IP. Mirrors
// snmp-discovery's detachForPrimaryIP. The standalone emitted IPAddress and
// Interface entities keep their full graph; only this snapshot is pruned.
func detachForPrimaryIP(ip *diode.IPAddress, owner *diode.Device) *diode.IPAddress {
	if ip == nil {
		return nil
	}
	snapshot := *ip
	if iface, ok := snapshot.AssignedObject.(*diode.Interface); ok && iface != nil {
		ifaceCopy := *iface
		if owner != nil {
			deviceCopy := *owner
			// Clear BOTH primary-IP fields on the embedded device copy so the
			// snapshot is independent of evaluation order between the v4 and v6
			// passes and carries no nested primary-IP sub-graph.
			deviceCopy.PrimaryIp4 = nil
			deviceCopy.PrimaryIp6 = nil
			deviceCopy.Config = nil // never embed the captured config in a nested ref
			ifaceCopy.Device = &deviceCopy
		}
		// Strip relationship pointers that can transitively reach a Device with a
		// primary IP set.
		ifaceCopy.Parent = nil
		ifaceCopy.Bridge = nil
		ifaceCopy.Lag = nil
		ifaceCopy.Module = nil
		snapshot.AssignedObject = &ifaceCopy
	}
	return &snapshot
}
