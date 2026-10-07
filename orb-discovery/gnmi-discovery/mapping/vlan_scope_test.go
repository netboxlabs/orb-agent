package mapping

import (
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
)

func unscopedVLAN() *diode.VLAN {
	vid := int64(101)
	return &diode.VLAN{Vid: &vid, Name: strptr("Voice")}
}

func TestCountUnscopedVLANs(t *testing.T) {
	grouped := unscopedVLAN()
	grouped.Group = &diode.VLANGroup{
		Name: strptr("Site A VLANs"), Slug: strptr("site-a-vlans"),
		Scope: &diode.Site{Name: strptr("Site A")},
	}

	sited := unscopedVLAN()
	sited.Site = &diode.Site{Name: strptr("Site A")}

	// applyDefaults always writes a site, so "no site at all" is the rare case
	// and the placeholder is the one operators actually hit.
	placeholder := unscopedVLAN()
	placeholder.Site = &diode.Site{Name: strptr(config.UndefinedPlaceholder)}

	groupedPlaceholder := unscopedVLAN()
	groupedPlaceholder.Site = &diode.Site{Name: strptr(config.UndefinedPlaceholder)}
	groupedPlaceholder.Group = &diode.VLANGroup{Name: strptr("g"), Slug: strptr("g")}

	// The remedy must not silence the warning without fixing anything: with no
	// defaults.site a configured group is scoped to the placeholder, which cannot
	// match the operator's group of the same name under a real site.
	placeholderGroup := unscopedVLAN()
	placeholderGroup.Site = &diode.Site{Name: strptr("Site A")}
	placeholderGroup.Group = &diode.VLANGroup{
		Name: strptr("Site A VLANs"), Slug: strptr("site-a-vlans"),
		Scope: &diode.Site{Name: strptr(config.UndefinedPlaceholder)},
	}

	realGroup := unscopedVLAN()
	realGroup.Site = &diode.Site{Name: strptr("Site A")}
	realGroup.Group = &diode.VLANGroup{
		Name: strptr("Site A VLANs"), Slug: strptr("site-a-vlans"),
		Scope: &diode.Site{Name: strptr("Site A")},
	}

	regionGroup := unscopedVLAN()
	regionGroup.Site = &diode.Site{Name: strptr("Site A")}
	regionGroup.Group = &diode.VLANGroup{
		Name: strptr("Brussels VLANs"), Slug: strptr("brussels-vlans"),
		Scope: &diode.Region{Name: strptr("Brussels")},
	}

	// The docs recommend a location scope for VLANs shared across sites, and the
	// builder hangs it off defaults.site — so without a real site it is a
	// location under a site named "undefined", which separates nothing.
	placeholderLocation := unscopedVLAN()
	placeholderLocation.Site = &diode.Site{Name: strptr("Site A")}
	placeholderLocation.Group = &diode.VLANGroup{
		Name: strptr("Campus VLANs"), Slug: strptr("campus-vlans"),
		Scope: &diode.Location{
			Name: strptr("Floor 3"),
			Site: &diode.Site{Name: strptr(config.UndefinedPlaceholder)},
		},
	}

	realLocation := unscopedVLAN()
	realLocation.Site = &diode.Site{Name: strptr("Site A")}
	realLocation.Group = &diode.VLANGroup{
		Name: strptr("Campus VLANs"), Slug: strptr("campus-vlans"),
		Scope: &diode.Location{
			Name: strptr("Floor 3"),
			Site: &diode.Site{Name: strptr("Site A")},
		},
	}

	// A group the builder emitted with no scope at all, and a location it could
	// not hang off a site. Neither resolves to the operator's group.
	scopelessGroup := unscopedVLAN()
	scopelessGroup.Group = &diode.VLANGroup{Name: strptr("Campus VLANs"), Slug: strptr("campus-vlans")}

	siteless := unscopedVLAN()
	siteless.Group = &diode.VLANGroup{
		Name: strptr("Campus VLANs"), Slug: strptr("campus-vlans"),
		Scope: &diode.Location{Name: strptr("Floor 3")},
	}

	tests := []struct {
		name     string
		entities []diode.Entity
		want     int
	}{
		{"neither group nor site is counted", []diode.Entity{unscopedVLAN()}, 1},
		{"a grouped VLAN is scoped", []diode.Entity{grouped}, 0},
		{"a real site is not a scope: a group-less VLAN still cannot match", []diode.Entity{sited}, 1},
		{"every unscoped VLAN counts", []diode.Entity{unscopedVLAN(), unscopedVLAN(), grouped}, 2},
		{"non-VLAN entities are ignored", []diode.Entity{&diode.Device{Name: strptr("rtr1")}, unscopedVLAN()}, 1},
		{"the placeholder site is not a scope either", []diode.Entity{placeholder}, 1},
		{"a group with no scope counts whatever site the VLAN carries", []diode.Entity{groupedPlaceholder}, 1},
		{"a typed-nil VLAN does not panic", []diode.Entity{(*diode.VLAN)(nil)}, 0},
		{"a group scoped only to the placeholder site is not a scope", []diode.Entity{placeholderGroup}, 1},
		{"a group scoped to a real site is a scope", []diode.Entity{realGroup}, 0},
		{"a non-site group scope is still a scope", []diode.Entity{regionGroup}, 0},
		{"a group scoped to a location under the placeholder site is not a scope", []diode.Entity{placeholderLocation}, 1},
		{"a group scoped to a location under a real site is a scope", []diode.Entity{realLocation}, 0},
		{"a group with no scope at all separates nothing", []diode.Entity{scopelessGroup}, 1},
		{"a location with no site cannot be resolved", []diode.Entity{siteless}, 1},
		{"no entities", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CountUnscopedVLANs(tt.entities); got != tt.want {
				t.Errorf("CountUnscopedVLANs() = %d, want %d", got, tt.want)
			}
		})
	}
}
