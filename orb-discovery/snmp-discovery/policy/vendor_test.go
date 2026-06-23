package policy

import (
	"testing"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/mapping"
)

func TestResolveVendor(t *testing.T) {
	tests := []struct {
		name        string
		sysObjectID string
		sysDescr    string
		want        string
	}{
		{"cisco prefix", ".1.3.6.1.4.1.9.1.1234", "Cisco IOS Software", "cisco"},
		{"cisco meraki", ".1.3.6.1.4.1.29671.5.1", "Meraki MS220", "cisco"},
		{"unknown enterprise", ".1.3.6.1.4.1.9999.1", "Unknown", ""},
		{"empty sysObjectID", "", "", ""},
		{"cisco no-dot prefix", "1.3.6.1.4.1.9.1.1234", "Cisco IOS Software", "cisco"},
		{"cisco no-dot meraki", "1.3.6.1.4.1.29671.5.1", "Meraki MS220", "cisco"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveVendor(tt.sysObjectID, tt.sysDescr, defaultVendorMatchers)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractSysIdentity(t *testing.T) {
	all := mapping.ObjectIDValueMap{
		".1.3.6.1.2.1.1.2.0": mapping.Value{Value: ".1.3.6.1.4.1.9.1.123", Type: mapping.ObjectIdentifier},
		".1.3.6.1.2.1.1.1.0": mapping.Value{Value: "Cisco IOS XE", Type: mapping.OctetString},
	}
	soid, sdescr := ExtractSysIdentity(all)
	if soid != ".1.3.6.1.4.1.9.1.123" || sdescr != "Cisco IOS XE" {
		t.Errorf("got (%q, %q), want (.1.3.6.1.4.1.9.1.123, Cisco IOS XE)", soid, sdescr)
	}
}
