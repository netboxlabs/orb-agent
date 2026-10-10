package mapping

import (
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
)

// Each option drops its own entity kind. With addresses off the subinterface
// that only an address revealed is still sent, and there is no primary IP.
func TestTranslateWithOptions_EmitPrefixesAndIPAddresses(t *testing.T) {
	store, _ := LoadProfiles("")
	base, _ := store.Get("_base")
	snap := map[string]any{
		"/system/state/hostname": "r1",
		"/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index=0]/ipv4/addresses/address[ip=10.0.0.1]/state/prefix-length":   24,
		"/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index=10]/ipv4/addresses/address[ip=192.0.2.1]/state/prefix-length": 24,
	}
	on, off := true, false
	for _, tc := range []struct {
		name                        string
		opts                        *config.Options
		wantAddresses, wantPrefixes bool
	}{
		{"no options", nil, true, true},
		{"defaults", &config.Options{}, true, true},
		{"explicitly on", &config.Options{EmitPrefixes: &on, EmitIPAddresses: &on}, true, true},
		{"no prefixes", &config.Options{EmitPrefixes: &off}, true, false},
		{"no addresses", &config.Options{EmitIPAddresses: &off}, false, true},
		{"neither", &config.Options{EmitPrefixes: &off, EmitIPAddresses: &off}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ents := TranslateWithOptions(base, snap, &config.Defaults{}, "", tc.opts, nil)
			var addrs, prefixes, names []string
			for _, e := range ents {
				switch v := e.(type) {
				case *diode.IPAddress:
					addrs = append(addrs, v.GetAddress())
				case *diode.Prefix:
					prefixes = append(prefixes, v.GetPrefix())
				case *diode.Interface:
					names = append(names, v.GetName())
				}
			}
			if tc.wantAddresses {
				assert.ElementsMatch(t, []string{"10.0.0.1/24", "192.0.2.1/24"}, addrs)
			} else {
				assert.Empty(t, addrs)
				assert.Nil(t, AssignPrimaryIP(ents, "10.0.0.1"))
			}
			if tc.wantPrefixes {
				assert.ElementsMatch(t, []string{"10.0.0.0/24", "192.0.2.0/24"}, prefixes)
			} else {
				assert.Empty(t, prefixes)
			}
			require.Contains(t, names, "Ethernet1.10")
		})
	}
}
