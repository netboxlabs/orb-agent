package mapping

import (
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
// hwVlanPorts (column 3) is deliberately not read: it is a PortList keyed
// by bridge port, and these devices expose no dot1dBasePortIfIndex to
// translate it with. Per-port membership for this vendor belongs here when
// a translation source is found.
const (
	oidHwVlanIndex     = ".1.3.6.1.4.1.2011.5.6.1.1.1.1."
	oidHwVlanName      = ".1.3.6.1.4.1.2011.5.6.1.1.1.2."
	oidHwVlanRowStatus = ".1.3.6.1.4.1.2011.5.6.1.1.1.13."
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
