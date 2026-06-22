package mapping

import (
	"sort"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
)

// parseNetworkInstanceStatePath extracts (niName, leaf) for the NI state leaves we
// curate (type, route-distinguisher). The NI name is the identity for VRF matching.
// Any other leaf (or the vlans/config subtrees) returns ok=false.
func parseNetworkInstanceStatePath(path string) (niName, leaf string, ok bool) {
	const niList = "/network-instances/network-instance"
	if !strings.HasPrefix(path, niList+"[") {
		return "", "", false
	}
	rest := path[len(niList):]
	niName, rest, ok = firstKeyVal(rest)
	if !ok {
		return "", "", false
	}
	const state = "/state/"
	if !strings.HasPrefix(rest, state) {
		return "", "", false
	}
	leaf = rest[len(state):]
	switch leaf {
	case "type", "route-distinguisher":
		return niName, leaf, true
	}
	return "", "", false
}

// parseNetworkInstanceIfacePath extracts (niName, id, leaf) for the NI
// interface-membership leaves (interface, subinterface). Doubly-keyed: two
// firstKeyVal passes (network-instance[name], interface[id]).
func parseNetworkInstanceIfacePath(path string) (niName, id, leaf string, ok bool) {
	const niList = "/network-instances/network-instance"
	if !strings.HasPrefix(path, niList+"[") {
		return "", "", "", false
	}
	rest := path[len(niList):]
	niName, rest, ok = firstKeyVal(rest)
	if !ok {
		return "", "", "", false
	}
	const ifList = "/interfaces/interface"
	if !strings.HasPrefix(rest, ifList+"[") {
		return "", "", "", false
	}
	rest = rest[len(ifList):]
	id, rest, ok = firstKeyVal(rest)
	if !ok {
		return "", "", "", false
	}
	const state = "/state/"
	if !strings.HasPrefix(rest, state) {
		return "", "", "", false
	}
	leaf = rest[len(state):]
	switch leaf {
	case "interface", "subinterface":
		return niName, id, leaf, true
	}
	return "", "", "", false
}

// translateVrfs emits a VRF entity per L3VRF network-instance (RD set only when
// present — VRF matches by name, so name-only is dup-safe) and returns a map from
// member interface-entity name (base "Eth2" or child subif "Eth2.100") to its VRF,
// for the binding post-pass in Translate. DEFAULT_INSTANCE / L2 instances are not
// VRFs; their members stay global.
func translateVrfs(snap map[string]any, defaults *config.Defaults) ([]diode.Entity, map[string]*diode.VRF) {
	// Per-policy VRF defaults, computed once (identical for every VRF).
	var vrfTenant *diode.Tenant
	var vrfDesc, vrfComments *string
	var vrfTags []*diode.Tag
	if defaults != nil {
		d := defaults.Vrf
		if d.Tenant != "" {
			vrfTenant = &diode.Tenant{Name: strptr(d.Tenant)}
		}
		if d.Description != "" {
			vrfDesc = strptr(d.Description)
		}
		if d.Comments != "" {
			vrfComments = strptr(d.Comments)
		}
		// VRF tags = policy-level tags + vrf-level tags, de-duped clone.
		vrfTags = toTags(append(append([]string{}, defaults.Tags...), d.Tags...))
	}

	type niState struct{ typ, rd string }
	type member struct{ baseIface, subif string }
	states := map[string]*niState{}
	members := map[string]map[string]*member{}

	paths := make([]string, 0, len(snap))
	for p := range snap {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, path := range paths {
		if ni, leaf, ok := parseNetworkInstanceStatePath(path); ok {
			s := states[ni]
			if s == nil {
				s = &niState{}
				states[ni] = s
			}
			switch leaf {
			case "type":
				s.typ = identityRefBase(snap[path])
			case "route-distinguisher":
				s.rd = strings.TrimSpace(toStr(snap[path]))
			}
			continue
		}
		if ni, id, leaf, ok := parseNetworkInstanceIfacePath(path); ok {
			m := members[ni]
			if m == nil {
				m = map[string]*member{}
				members[ni] = m
			}
			e := m[id]
			if e == nil {
				e = &member{}
				m[id] = e
			}
			switch leaf {
			case "interface":
				e.baseIface = toStr(snap[path])
			case "subinterface":
				e.subif = toStr(snap[path])
			}
		}
	}

	niNames := make([]string, 0, len(states))
	for ni := range states {
		niNames = append(niNames, ni)
	}
	sort.Strings(niNames)

	vrfByIface := map[string]*diode.VRF{}
	var out []diode.Entity
	for _, ni := range niNames {
		if states[ni].typ != "L3VRF" {
			continue
		}
		v := &diode.VRF{
			Name:        strptr(ni),
			Tenant:      vrfTenant,
			Description: vrfDesc,
			Comments:    vrfComments,
		}
		if rd := states[ni].rd; rd != "" {
			v.Rd = strptr(rd)
		}
		if len(vrfTags) > 0 {
			v.Tags = vrfTags
		}
		out = append(out, v)
		for _, e := range members[ni] {
			base := strings.TrimSpace(e.baseIface)
			if base == "" {
				continue
			}
			name := base
			if idx := strings.TrimSpace(e.subif); idx != "" && idx != "0" {
				name = base + "." + idx
			}
			vrfByIface[name] = v
		}
	}
	return out, vrfByIface
}
