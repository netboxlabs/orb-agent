package mapping

import (
	"log/slog"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestIPAddressMapper() *IPAddressMapper {
	return &IPAddressMapper{logger: slog.Default()}
}

func afDefaults() *config.Defaults {
	return &config.Defaults{
		IPAddress: config.IPAddressDefaults{
			Vrf:     config.VrfParameters{Name: "vrf-any", Rd: "65000:1"},
			VrfIpv4: config.VrfParameters{Name: "vrf-four"},
			VrfIpv6: config.VrfParameters{Name: "vrf-six", Rd: "65000:6"},
		},
	}
}

func TestIPAddressMapper_applyDefaults_VrfIpv4Wins(t *testing.T) {
	m := newTestIPAddressMapper()
	entity := &diode.IPAddress{Address: strPtr("192.0.2.10/24")}
	m.applyDefaults(entity, afDefaults())
	require.NotNil(t, entity.Vrf)
	assert.Equal(t, "vrf-four", *entity.Vrf.Name)
	// The AF override carries no rd — none must leak from the
	// AF-agnostic default.
	assert.Nil(t, entity.Vrf.Rd)
}

func TestIPAddressMapper_applyDefaults_VrfIpv6Wins(t *testing.T) {
	m := newTestIPAddressMapper()
	entity := &diode.IPAddress{Address: strPtr("2001:db8::1/64")}
	m.applyDefaults(entity, afDefaults())
	require.NotNil(t, entity.Vrf)
	assert.Equal(t, "vrf-six", *entity.Vrf.Name)
	require.NotNil(t, entity.Vrf.Rd)
	assert.Equal(t, "65000:6", *entity.Vrf.Rd)
}

func TestIPAddressMapper_applyDefaults_FallsBackToAgnosticVrf(t *testing.T) {
	m := newTestIPAddressMapper()
	defaults := afDefaults()
	defaults.IPAddress.VrfIpv4 = config.VrfParameters{}
	entity := &diode.IPAddress{Address: strPtr("192.0.2.10/24")}
	m.applyDefaults(entity, defaults)
	require.NotNil(t, entity.Vrf)
	assert.Equal(t, "vrf-any", *entity.Vrf.Name)
	require.NotNil(t, entity.Vrf.Rd)
	assert.Equal(t, "65000:1", *entity.Vrf.Rd)
}

func TestIPAddressMapper_applyDefaults_AfMisconfigWarns(t *testing.T) {
	// rd-only AF override resolves to a nameless VrfParameters for that
	// family: the existing warn-once misconfig path must fire and no VRF
	// may be attached.
	m := newTestIPAddressMapper()
	defaults := &config.Defaults{
		IPAddress: config.IPAddressDefaults{
			VrfIpv4: config.VrfParameters{Rd: "65000:4"},
		},
	}
	entity := &diode.IPAddress{Address: strPtr("192.0.2.10/24")}
	m.applyDefaults(entity, defaults)
	assert.Nil(t, entity.Vrf)
}

func TestVrfForFamily_Resolution(t *testing.T) {
	d := &config.IPAddressDefaults{
		Vrf:     config.VrfParameters{Name: "any"},
		VrfIpv6: config.VrfParameters{Rd: "65000:6"},
	}
	v4, knob4 := d.VrfForFamily("ipv4")
	assert.Equal(t, "any", v4.Name)
	assert.Equal(t, "vrf", knob4)
	// Any set field on the AF override selects it wholesale — even a
	// nameless one (which the mapper then warns about and drops).
	v6, knob6 := d.VrfForFamily("ipv6")
	assert.Equal(t, "", v6.Name)
	assert.Equal(t, "vrf_ipv6", knob6)
	assert.Equal(t, "65000:6", v6.Rd)
}
