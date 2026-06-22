package mapping

import (
	"sort"
	"strconv"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"
)

// ocVlanMode maps an OpenConfig switched-vlan interface-mode (upper-cased) to a
// NetBox interface mode. OpenConfig has no clean "trunk all vlans" signal, so
// tagged-all is intentionally not inferred.
var ocVlanMode = map[string]string{
	"ACCESS": "access",
	"TRUNK":  "tagged",
}

const minVid, maxVid = int64(1), int64(4094)

// parseSwitchedVlanPath extracts (iface, leaf) from an OpenConfig switched-vlan
// path under ifaceListPath, for either the ethernet or aggregation container.
// leaf is one of interface-mode/access-vlan/native-vlan/trunk-vlans; any other
// path returns ok=false.
func parseSwitchedVlanPath(path, ifaceListPath string) (iface, leaf string, ok bool) {
	if ifaceListPath == "" || !strings.HasPrefix(path, ifaceListPath+"[") {
		return "", "", false
	}
	rest := path[len(ifaceListPath):]   // "[name=Ethernet1]/ethernet/switched-vlan/..."
	iface, rest, ok = firstKeyVal(rest) // shared helper from translate_ip.go
	if !ok {
		return "", "", false
	}
	switch {
	case strings.HasPrefix(rest, "/ethernet/switched-vlan/state/"):
		leaf = strings.TrimPrefix(rest, "/ethernet/switched-vlan/state/")
	case strings.HasPrefix(rest, "/aggregation/switched-vlan/state/"):
		leaf = strings.TrimPrefix(rest, "/aggregation/switched-vlan/state/")
	default:
		return "", "", false
	}
	switch leaf {
	case "interface-mode", "access-vlan", "native-vlan", "trunk-vlans":
		return iface, leaf, true
	}
	return "", "", false
}

// safeVid coerces a value to a VLAN id in [1,4094]. Booleans are rejected
// explicitly (bool is not a VLAN and some decoders surface unexpected types).
func safeVid(v any) (int64, bool) {
	switch n := v.(type) {
	case bool: // bool is not a VLAN; reject before any int coercion
		return 0, false
	case int:
		return checkVid(int64(n))
	case int64:
		return checkVid(n)
	case uint:
		return checkVid(int64(n))
	case uint8:
		return checkVid(int64(n))
	case uint16:
		return checkVid(int64(n))
	case uint32:
		return checkVid(int64(n))
	case uint64:
		return checkVid(int64(n))
	case float64:
		// Bounds-check before converting: an out-of-range float -> int64 is
		// implementation-defined in Go. Reject NaN (n != n) and anything outside
		// the VID range; values within it convert safely (checkVid re-validates).
		if n != n || n < float64(minVid) || n > float64(maxVid) {
			return 0, false
		}
		return checkVid(int64(n))
	case string:
		i, err := strconv.ParseInt(strings.TrimSpace(n), 10, 64)
		if err != nil {
			return 0, false
		}
		return checkVid(i)
	}
	return 0, false
}

func checkVid(i int64) (int64, bool) {
	if i < minVid || i > maxVid {
		return 0, false
	}
	return i, true
}

// translateSwitchports reads the switched-vlan leaves out of snap and sets Mode /
// UntaggedVlan / TaggedVlans on the interfaces in ifacesByName, sourcing VLAN
// objects from the shared builder b (which dedups by vid and owns emission).
func translateSwitchports(profile *Profile, snap map[string]any, b *vlanBuilder, ifacesByName map[string]*diode.Interface) {
	listPath := profile.Interfaces.ListPath
	if listPath == "" {
		return
	}
	type sp struct {
		mode      string
		accessVid any
		nativeVid any
		trunkRaw  any
	}
	perIface := map[string]*sp{}
	var order []string
	get := func(iface string) *sp {
		s, ok := perIface[iface]
		if !ok {
			s = &sp{}
			perIface[iface] = s
			order = append(order, iface)
		}
		return s
	}
	for path, val := range snap {
		iface, leaf, ok := parseSwitchedVlanPath(path, listPath)
		if !ok {
			continue
		}
		s := get(iface)
		switch leaf {
		case "interface-mode":
			s.mode = strings.ToUpper(strings.TrimSpace(toStr(val)))
		case "access-vlan":
			s.accessVid = val
		case "native-vlan":
			s.nativeVid = val
		case "trunk-vlans":
			s.trunkRaw = val
		}
	}

	sort.Strings(order)
	for _, ifaceName := range order {
		s := perIface[ifaceName]
		mode, ok := ocVlanMode[s.mode]
		if !ok {
			continue
		}
		iface := ifacesByName[ifaceName]
		if iface == nil {
			continue
		}
		iface.Mode = strptr(mode)

		var untaggedVid int64
		haveUntagged := false
		if mode == "access" {
			if vid, okVid := safeVid(s.accessVid); okVid {
				untaggedVid, haveUntagged = vid, true
			}
		} else {
			if vid, okVid := safeVid(s.nativeVid); okVid {
				untaggedVid, haveUntagged = vid, true
			}
		}
		if haveUntagged {
			iface.UntaggedVlan = b.get(untaggedVid)
		}
		if mode == "tagged" {
			for _, vid := range expandTrunkVlans(s.trunkRaw) {
				if haveUntagged && vid == untaggedVid {
					continue
				}
				iface.TaggedVlans = append(iface.TaggedVlans, b.get(vid))
			}
		}
	}
}

// expandTrunkVlans parses a trunk-vlans leaf-list value (a []any of vids and
// "lo..hi" range strings, or a lone scalar) into a sorted, deduped []int64 in
// [1,4094]. Range ends are parsed loosely then clamped (lo up to 1, hi down to
// 4094) and reversed/out-of-range ranges (lo>hi after clamp) are skipped, so a
// malformed huge range stays bounded to <=4094 iterations.
func expandTrunkVlans(v any) []int64 {
	items, ok := v.([]any)
	if !ok {
		items = []any{v} // tolerate a lone scalar
	}
	set := map[int64]struct{}{}
	for _, it := range items {
		if s, isStr := it.(string); isStr && strings.Contains(s, "..") {
			parts := strings.SplitN(s, "..", 2)
			// Loose parse (NOT safeVid, which REJECTS out-of-range) so we can CLAMP
			// the ends — this is what bounds a malformed huge range to <=4094
			// iterations (the unbounded-range fix) while still expanding it.
			lo, errLo := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
			hi, errHi := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
			if errLo != nil || errHi != nil {
				continue
			}
			if lo < minVid {
				lo = minVid
			}
			if hi > maxVid {
				hi = maxVid // clamp upper end -> at most 4094 iterations
			}
			if lo > hi { // reversed (e.g. "10..5") or fully out-of-range (e.g. "5000..6000" -> 5000>4094)
				continue
			}
			for i := lo; i <= hi; i++ {
				set[i] = struct{}{}
			}
			continue
		}
		if vid, okVid := safeVid(it); okVid {
			set[vid] = struct{}{}
		}
	}
	out := make([]int64, 0, len(set))
	for vid := range set {
		out = append(out, vid)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
