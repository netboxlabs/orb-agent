package policy

import (
	"regexp"
	"strings"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/mapping"
)

const (
	oidSysObjectID = ".1.3.6.1.2.1.1.2.0"
	oidSysDescr    = ".1.3.6.1.2.1.1.1.0"
)

// VendorMatcher resolves a vendor key from a host's identity tuple.
// All checks within a matcher are AND'ed; the first matcher that
// passes wins. See spec rev. 3 §"Vendor dispatch (composite matching)".
type VendorMatcher struct {
	Vendor              string
	SysObjectIDPrefixes []string
	SysDescrRegex       *regexp.Regexp
}

// defaultVendorMatchers is the v1 vendor table. Order matters: more
// specific matchers should appear before more general ones.
var defaultVendorMatchers = []VendorMatcher{
	{
		Vendor: "cisco",
		SysObjectIDPrefixes: []string{
			".1.3.6.1.4.1.9.",     // Cisco Systems
			".1.3.6.1.4.1.29671.", // Meraki (Cisco-acquired; distinct enterprise)
		},
	},
	// Future vendors append here.
}

// ResolveVendor returns the matching vendor key (e.g., "cisco") or ""
// when no matcher fits. The caller treats "" as "generic only".
func ResolveVendor(sysObjectID, sysDescr string, matchers []VendorMatcher) string {
	if sysObjectID == "" {
		return ""
	}
	for _, m := range matchers {
		if !sysObjectIDMatches(sysObjectID, m.SysObjectIDPrefixes) {
			continue
		}
		if m.SysDescrRegex != nil && !m.SysDescrRegex.MatchString(sysDescr) {
			continue
		}
		return m.Vendor
	}
	return ""
}

func sysObjectIDMatches(sysObjectID string, prefixes []string) bool {
	sysObjectID = strings.TrimPrefix(sysObjectID, ".")
	for _, p := range prefixes {
		p = strings.TrimPrefix(p, ".")
		if strings.HasPrefix(sysObjectID, p) {
			return true
		}
	}
	return false
}

// ExtractSysIdentity reads sysObjectID and sysDescr from a flat
// ObjectIDValueMap. Returned values are "" if the OID is absent.
func ExtractSysIdentity(all mapping.ObjectIDValueMap) (sysObjectID, sysDescr string) {
	if v, ok := all[oidSysObjectID]; ok {
		sysObjectID = v.Value
	}
	if v, ok := all[oidSysDescr]; ok {
		sysDescr = v.Value
	}
	return
}
