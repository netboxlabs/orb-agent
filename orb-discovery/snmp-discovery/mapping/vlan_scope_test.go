package mapping

import (
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

func unscopedVLAN() *diode.VLAN {
	return &diode.VLAN{Vid: int64Ptr(101), Name: strPtr("Voice")}
}

func TestCountUnscopedVLANs(t *testing.T) {
	grouped := unscopedVLAN()
	grouped.Group = &diode.VLANGroup{
		Name: strPtr("Site A VLANs"), Slug: strPtr("site-a-vlans"),
		Scope: &diode.Site{Name: strPtr("Site A")},
	}

	sited := unscopedVLAN()
	sited.Site = &diode.Site{Name: strPtr("Site A")}

	// The remedy must not silence the warning without fixing anything: with no
	// defaults.site a configured group is scoped to the placeholder, which cannot
	// match the operator's group of the same name under a real site.
	placeholderGroup := unscopedVLAN()
	placeholderGroup.Site = nil
	placeholderGroup.Group = &diode.VLANGroup{
		Name: strPtr("Site A VLANs"), Slug: strPtr("site-a-vlans"),
		Scope: &diode.Site{Name: strPtr(config.UndefinedPlaceholder)},
	}

	realGroup := unscopedVLAN()
	realGroup.Site = nil
	realGroup.Group = &diode.VLANGroup{
		Name: strPtr("Site A VLANs"), Slug: strPtr("site-a-vlans"),
		Scope: &diode.Site{Name: strPtr("Site A")},
	}

	regionGroup := unscopedVLAN()
	regionGroup.Site = nil
	regionGroup.Group = &diode.VLANGroup{
		Name: strPtr("Brussels VLANs"), Slug: strPtr("brussels-vlans"),
		Scope: &diode.Region{Name: strPtr("Brussels")},
	}

	// The docs recommend a location scope for VLANs shared across sites, and the
	// builder hangs it off defaults.site — so without a real site it is a
	// location under a site named "undefined", which separates nothing.
	placeholderLocation := unscopedVLAN()
	placeholderLocation.Site = nil
	placeholderLocation.Group = &diode.VLANGroup{
		Name: strPtr("Campus VLANs"), Slug: strPtr("campus-vlans"),
		Scope: &diode.Location{
			Name: strPtr("Floor 3"),
			Site: &diode.Site{Name: strPtr(config.UndefinedPlaceholder)},
		},
	}

	realLocation := unscopedVLAN()
	realLocation.Site = nil
	realLocation.Group = &diode.VLANGroup{
		Name: strPtr("Campus VLANs"), Slug: strPtr("campus-vlans"),
		Scope: &diode.Location{
			Name: strPtr("Floor 3"),
			Site: &diode.Site{Name: strPtr("Site A")},
		},
	}

	// A group the builder emitted with no scope at all, and a location it could
	// not hang off a site. Neither resolves to the operator's group.
	scopelessGroup := unscopedVLAN()
	scopelessGroup.Group = &diode.VLANGroup{Name: strPtr("Campus VLANs"), Slug: strPtr("campus-vlans")}

	siteless := unscopedVLAN()
	siteless.Group = &diode.VLANGroup{
		Name: strPtr("Campus VLANs"), Slug: strPtr("campus-vlans"),
		Scope: &diode.Location{Name: strPtr("Floor 3")},
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
		{"non-VLAN entities are ignored", []diode.Entity{&diode.Device{Name: strPtr("rtr1")}, unscopedVLAN()}, 1},
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
