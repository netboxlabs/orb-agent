package mapping_test

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/mapping"
)

// onIfIndex rebinds an ipAddressTable row from ifIndex 1 to ifIndex by
// rewriting its ipAddressIfIndex column and the ifIndex in its prefix
// pointer.
func onIfIndex(pdus mapping.ObjectIDValueMap, ifIndex string) mapping.ObjectIDValueMap {
	const prefixRow = ".1.3.6.1.2.1.4.32.1.5."
	for oid, v := range pdus {
		switch {
		case strings.HasPrefix(string(oid), ".1.3.6.1.2.1.4.34.1.3."):
			v.Value = ifIndex
		case strings.HasPrefix(string(oid), ".1.3.6.1.2.1.4.34.1.5."):
			v.Value = strings.Replace(v.Value, prefixRow+"1.", prefixRow+ifIndex+".", 1)
		}
		pdus[oid] = v
	}
	return pdus
}

// linkLocalWalk has a global IPv6 address on Gi0, IPv6 link-locals at both
// ends of fe80::/10, addresses just outside that range, IPv4 link-locals,
// and a second interface whose only address is a link-local.
func linkLocalWalk() mapping.ObjectIDValueMap {
	return mergeOIDs(
		primaryIPModernIPv6OIDs("2001:db8::1", "Gi0", 64),
		modernIPv6PDUs("fe80::1", 64),
		modernIPv6PDUs("febf:ffff::1", 64),
		modernIPv6PDUs("fe7f:ffff::1", 64),
		modernIPv6PDUs("fec0::1", 64),
		modernIPv4PDUs("169.254.10.5", 16),
		modernIPv4MappedPDUs("169.254.10.6"),
		mapping.ObjectIDValueMap{".1.3.6.1.2.1.2.2.1.2.2": mapping.Value{
			Value: "Gi1", Type: mapping.Asn1BER(mapping.OctetString), IdentifierSize: 1,
		}},
		onIfIndex(modernIPv6PDUs("fe80::2", 64), "2"),
	)
}

func mapLinkLocalWalk(t *testing.T, options config.Options) []diode.Entity {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg, err := mapping.NewConfig(primaryIPFixtureBothTables(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, options)
	require.NoError(t, err)
	return mapping.NewObjectIDMapper(cfg, logger, &config.Defaults{}, "").MapObjectIDsToEntity(linkLocalWalk())
}

func sentAddresses(entities []diode.Entity) []string {
	var out []string
	for _, e := range entities {
		if ip, ok := e.(*diode.IPAddress); ok && ip.Address != nil {
			out = append(out, *ip.Address)
		}
	}
	return out
}

// interfaceSent reports whether an interface named name is sent, on its own
// or nested in an address.
func interfaceSent(entities []diode.Entity, name string) bool {
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.Interface:
			if v.Name != nil && *v.Name == name {
				return true
			}
		case *diode.IPAddress:
			if iface, ok := v.AssignedObject.(*diode.Interface); ok && iface != nil && iface.Name != nil && *iface.Name == name {
				return true
			}
		}
	}
	return false
}

// ipv6LinkLocal and keptOutsideIPv6LinkLocal split the addresses of
// linkLocalWalk at fe80::/10.
var (
	ipv6LinkLocal            = []string{"fe80::1/", "febf:ffff::1/", "fe80::2/"}
	keptOutsideIPv6LinkLocal = []string{
		"2001:db8::1/", "fe7f:ffff::1/", "fec0::1/", "169.254.10.5/", "::ffff:169.254.10.6/",
	}
)

// TestIPv6LinkLocalAddresses_NotSentByDefault covers the default of
// emit_ipv6_link_local_addresses. A link-local address is only unique on its
// own link, while Diode matches an IP address by address and VRF, so the same
// fe80:: address on two interfaces would land on one NetBox object.
func TestIPv6LinkLocalAddresses_NotSentByDefault(t *testing.T) {
	for name, options := range map[string]config.Options{
		"unset":          {},
		"explicit false": {EmitIPv6LinkLocalAddresses: boolPtr(false)},
	} {
		t.Run(name, func(t *testing.T) {
			entities := mapLinkLocalWalk(t, options)
			for _, addr := range ipv6LinkLocal {
				assert.Nil(t, survivingIPFor(entities, addr), "the IPv6 link-local %s must not be sent", addr)
			}
			for _, want := range keptOutsideIPv6LinkLocal {
				assert.NotNil(t, survivingIPFor(entities, want), "%s is outside fe80::/10 and must be sent", want)
			}
			assert.True(t, interfaceSent(entities, "Gi1"),
				"an interface whose only address is a link-local must still be sent")
		})
	}
}

func TestIPv6LinkLocalAddresses_SentWithTheOptIn(t *testing.T) {
	entities := mapLinkLocalWalk(t, config.Options{EmitIPv6LinkLocalAddresses: boolPtr(true)})
	for _, want := range []string{"fe80::1/64", "febf:ffff::1/64", "fe80::2/64"} {
		assert.Contains(t, sentAddresses(entities), want)
	}
	assert.True(t, interfaceSent(entities, "Gi1"))
	for _, want := range keptOutsideIPv6LinkLocal {
		assert.NotNil(t, survivingIPFor(entities, want), "%s must be sent", want)
	}
}

// TestIPv6LinkLocalAddresses_JudgedOnTheAddress keeps a mask wider than /10
// from letting a link-local address through.
func TestIPv6LinkLocalAddresses_JudgedOnTheAddress(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg, err := mapping.NewConfig(primaryIPFixtureBothTables(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
	require.NoError(t, err)
	entities := mapping.NewObjectIDMapper(cfg, logger, &config.Defaults{}, "").MapObjectIDsToEntity(mergeOIDs(
		primaryIPModernIPv6OIDs("2001:db8::1", "Gi0", 64),
		modernIPv6PDUs("fe80::1", 8),
	))
	assert.Equal(t, []string{"2001:db8::1/64"}, sentAddresses(entities))
}

func TestOptions_IPv6LinkLocalAddressEmissionEnabled(t *testing.T) {
	assert.False(t, (*config.Options)(nil).IPv6LinkLocalAddressEmissionEnabled(), "nil options")
	assert.False(t, (&config.Options{}).IPv6LinkLocalAddressEmissionEnabled(), "unset")
	assert.False(t, (&config.Options{EmitIPv6LinkLocalAddresses: boolPtr(false)}).IPv6LinkLocalAddressEmissionEnabled())
	assert.True(t, (&config.Options{EmitIPv6LinkLocalAddresses: boolPtr(true)}).IPv6LinkLocalAddressEmissionEnabled())
}
