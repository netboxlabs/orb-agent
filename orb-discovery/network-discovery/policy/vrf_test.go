package policy

import (
	"io"
	"log/slog"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/config"
)

func vrfOf(t *testing.T, defaults config.Defaults) (*diode.VRF, *diode.IPAddress) {
	t.Helper()
	r := &Runner{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		config: config.PolicyConfig{Defaults: defaults},
	}
	ip, _ := r.ipAddressEntity(scannedHost("host.example.net"), "192.0.2.10/24", "192.0.2.10", "p")
	return ip.Vrf, ip
}

func TestIPAddressEntity_VrfTenant(t *testing.T) {
	vrf, ip := vrfOf(t, config.Defaults{
		Vrf: config.VrfParameters{
			Name:   "MyVRF",
			Tenant: config.TenantParameters{Name: "acme", Group: "customers"},
		},
		Tenant: config.TenantParameters{Name: "other"},
	})

	require.NotNil(t, vrf)
	assert.Equal(t, "MyVRF", vrf.GetName())
	require.NotNil(t, vrf.Tenant)
	assert.Equal(t, "acme", vrf.Tenant.GetName())
	require.NotNil(t, vrf.Tenant.Group)
	assert.Equal(t, "customers", vrf.Tenant.Group.GetName())
	require.NotNil(t, ip.Tenant)
	assert.Equal(t, "other", ip.Tenant.GetName(), "the IP keeps defaults.tenant")
}

func TestIPAddressEntity_VrfDoesNotInheritDefaultsTenant(t *testing.T) {
	vrf, ip := vrfOf(t, config.Defaults{
		Vrf:    config.VrfParameters{Name: "MyVRF"},
		Tenant: config.TenantParameters{Name: "acme", Group: "customers"},
	})

	require.NotNil(t, vrf)
	assert.Nil(t, vrf.Tenant, "a VRF without its own tenant must stay tenant-less")
	require.NotNil(t, ip.Tenant)
	assert.Equal(t, "acme", ip.Tenant.GetName())
}

func TestIPAddressEntity_VrfRd(t *testing.T) {
	for _, tc := range []struct {
		name             string
		vrfRd, defaultRd string
		want             string
	}{
		{name: "vrf rd", vrfRd: "65000:1", want: "65000:1"},
		{name: "defaults rd", defaultRd: "65000:2", want: "65000:2"},
		{name: "both, equal", vrfRd: "65000:3", defaultRd: "65000:3", want: "65000:3"},
		{name: "neither"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vrf, _ := vrfOf(t, config.Defaults{
				Vrf: config.VrfParameters{Name: "MyVRF", Rd: tc.vrfRd},
				Rd:  tc.defaultRd,
			})
			require.NotNil(t, vrf)
			if tc.want == "" {
				assert.Nil(t, vrf.Rd)
				return
			}
			require.NotNil(t, vrf.Rd)
			assert.Equal(t, tc.want, *vrf.Rd)
		})
	}
}

func TestIPAddressEntity_VrfMetadata(t *testing.T) {
	vrf, _ := vrfOf(t, config.Defaults{
		Vrf: config.VrfParameters{
			Name:        "MyVRF",
			Description: "vrf description",
			Comments:    "vrf comments",
			Tags:        []string{"a", "b"},
		},
	})

	require.NotNil(t, vrf)
	require.NotNil(t, vrf.Description)
	assert.Equal(t, "vrf description", *vrf.Description)
	require.NotNil(t, vrf.Comments)
	assert.Equal(t, "vrf comments", *vrf.Comments)
	require.Len(t, vrf.Tags, 2)
	assert.Equal(t, "a", vrf.Tags[0].GetName())
	assert.Equal(t, "b", vrf.Tags[1].GetName())
}

func TestIPAddressEntity_VrfLeavesUnsetFieldsNil(t *testing.T) {
	vrf, _ := vrfOf(t, config.Defaults{
		Vrf:         config.VrfParameters{Name: "MyVRF"},
		Description: "ip description",
		Comments:    "ip comments",
		Tags:        []string{"ip-tag"},
	})

	require.NotNil(t, vrf)
	assert.Nil(t, vrf.Description, "defaults.description belongs to the IP, not the VRF")
	assert.Nil(t, vrf.Comments)
	assert.Empty(t, vrf.Tags)
	assert.Nil(t, vrf.Tenant)
}

func TestIPAddressEntity_NoVrf(t *testing.T) {
	vrf, _ := vrfOf(t, config.Defaults{Rd: "65000:1"})
	assert.Nil(t, vrf)
}
