package mapping_test

import (
	"log/slog"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/mapping"
)

func TestResolveInterfaceType_DottedNameNeedsTheOtherNameToAgree(t *testing.T) {
	tests := []struct {
		name          string
		interfaceName string
		alternateName string
		ifType        string
		speed         *int64
		want          string
	}{
		// The other name has no dot, so the reported ifType decides.
		{"radio port", "radio.if0", "Radio1", "188", nil, "other-wireless"},
		{"version string in ifDescr", "Switch R3.00.012 Port 13 on Unit 1", "1/13", "6", int64Ptr(1000000), "1000base-t"},
		{"aggregate", "lag 901 Access Node 8.1.4", "lag 901", "161", nil, "lag"},
		{"ifType that maps to virtual", "radio.if0", "Radio1", "135", nil, "virtual"},
		{"other name split by a colon only", "radio.if0", "radio:if0", "188", nil, "other-wireless"},

		// Both names carry the dot: a unit, whatever its ifType.
		{"unit on an Ethernet port", "eth0.100", "eth0.100", "6", int64Ptr(1000000), "virtual"},
		{"unit named differently in each", "GigabitEthernet0/0.100", "Gi0/0.100", "6", int64Ptr(1000000), "virtual"},
		{"letter suffix in both", "pxc-1.a, Port cross-connect", "pxc-1.a", "6", int64Ptr(1000000), "virtual"},
		{"routed unit with text after the name", `lag-11.100, IP interface, "private"`, "lag-11.100", "142", nil, "virtual"},

		// The other name is no evidence: the dot still decides.
		{"no other name", "radio.if0", "", "188", nil, "virtual"},
		{"descriptive other name", "radio.if0", "Unit: 1 Slot: 0 Port: 1", "188", nil, "virtual"},
		{"placeholder other name", "radio.if0", mapping.DefaultInterfaceName, "188", nil, "virtual"},

		// An ifType with no mapping says nothing against the name.
		{"unmapped ifType", "rif0(192.0.2.1)", "System", "142", nil, "virtual"},

		// The colon rule is unchanged.
		{"colon child with logical ifType", "lag-16:2210", "lag16-2210", "161", nil, "virtual"},
		{"colon lane", "ge-0/0/0:0", "lane0", "6", int64Ptr(1000000), "1000base-t"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapping.ResolveInterfaceType(tt.interfaceName, tt.alternateName, tt.ifType, tt.speed, "", nil, 0)
			assert.Equal(t, tt.want, got)
		})
	}
}

// interfaceRow is one ifTable/ifXTable row as the interface mapper receives it.
func interfaceRow(index, ifDescr, ifName, ifType string) map[mapping.ObjectIDIndex]*mapping.ObjectIDValue {
	row := map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{}
	add := func(parent, value string, typ mapping.Asn1BER) {
		if value == "" {
			return
		}
		oid := parent + "." + index
		row[mapping.ObjectIDIndex(oid)] = &mapping.ObjectIDValue{OID: oid, Index: mapping.ObjectIDIndex(index), Parent: parent, Value: value, Type: typ}
	}
	add("1.3.6.1.2.1.2.2.1.2", ifDescr, mapping.OctetString)
	add("1.3.6.1.2.1.31.1.1.1.1", ifName, mapping.OctetString)
	add("1.3.6.1.2.1.2.2.1.3", ifType, mapping.Integer)
	return row
}

var interfaceRowEntry = &mapping.Entry{
	OID:    "1.3.6.1.2.1.2.2.1",
	Entity: "interface",
	Field:  "_id",
	MappingEntries: []mapping.Entry{
		{OID: "1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
		{OID: "1.3.6.1.2.1.31.1.1.1.1", Entity: "interface", Field: "name_alternate"},
		{OID: "1.3.6.1.2.1.2.2.1.3", Entity: "interface", Field: "type"},
	},
}

func mapInterfaceRow(t *testing.T, mapper *mapping.InterfaceMapper, registry *mapping.EntityRegistry, index, ifDescr, ifName, ifType string) *diode.Interface {
	t.Helper()
	iface, ok := mapper.Map(interfaceRow(index, ifDescr, ifName, ifType), interfaceRowEntry, registry, &config.Defaults{}).(*diode.Interface)
	require.True(t, ok)
	return iface
}

func TestInterfaceMapper_DottedNameTheOtherNameDisputes(t *testing.T) {
	logger := slog.Default()

	t.Run("keeps the ifDescr name and types from ifType", func(t *testing.T) {
		mapper, err := mapping.NewInterfaceMapper(logger, nil, config.InterfaceNameSourceAuto)
		require.NoError(t, err)
		iface := mapInterfaceRow(t, mapper, mapping.NewEntityRegistry(logger), "1", "radio.if0", "Radio1", "188")
		assert.Equal(t, "radio.if0", *iface.Name)
		assert.Equal(t, "other-wireless", *iface.Type)
	})

	t.Run("an ifName source weighs ifDescr", func(t *testing.T) {
		mapper, err := mapping.NewInterfaceMapper(logger, nil, config.InterfaceNameSourceIfName)
		require.NoError(t, err)
		iface := mapInterfaceRow(t, mapper, mapping.NewEntityRegistry(logger), "1", "Radio1", "radio.if0", "188")
		assert.Equal(t, "radio.if0", *iface.Name)
		assert.Equal(t, "other-wireless", *iface.Type)
	})

	t.Run("both names dotted stays a unit", func(t *testing.T) {
		mapper, err := mapping.NewInterfaceMapper(logger, nil, config.InterfaceNameSourceAuto)
		require.NoError(t, err)
		iface := mapInterfaceRow(t, mapper, mapping.NewEntityRegistry(logger), "1", "GigabitEthernet0/0.100", "Gi0/0.100", "188")
		assert.Equal(t, "virtual", *iface.Type)
	})

	t.Run("user patterns apply once the name is disputed", func(t *testing.T) {
		mapper, err := mapping.NewInterfaceMapper(logger, []config.InterfacePattern{{Match: `^radio\.`, Type: "other"}}, config.InterfaceNameSourceAuto)
		require.NoError(t, err)
		iface := mapInterfaceRow(t, mapper, mapping.NewEntityRegistry(logger), "1", "radio.if0", "Radio1", "188")
		assert.Equal(t, "other", *iface.Type)
	})
}

func TestResolveSubinterfaceParents_DisputedDottedName(t *testing.T) {
	logger := slog.Default()

	t.Run("parent on the device keeps it a unit", func(t *testing.T) {
		mapper, err := mapping.NewInterfaceMapper(logger, nil, config.InterfaceNameSourceAuto)
		require.NoError(t, err)
		registry := mapping.NewEntityRegistry(logger)
		child := mapInterfaceRow(t, mapper, registry, "2", "radio.if0", "Radio1", "188")
		mapInterfaceRow(t, mapper, registry, "1", "radio", "radio", "188")

		registry.ResolveSubinterfaceParents()

		assert.Equal(t, "virtual", *child.Type)
		if assert.NotNil(t, child.Parent) {
			assert.Equal(t, "radio", *child.Parent.Name)
		}
	})

	t.Run("no parent on the device keeps the ifType", func(t *testing.T) {
		mapper, err := mapping.NewInterfaceMapper(logger, nil, config.InterfaceNameSourceAuto)
		require.NoError(t, err)
		registry := mapping.NewEntityRegistry(logger)
		child := mapInterfaceRow(t, mapper, registry, "2", "radio.if0", "Radio1", "188")
		mapInterfaceRow(t, mapper, registry, "1", "Radio0", "Radio0", "188")

		registry.ResolveSubinterfaceParents()

		assert.Equal(t, "other-wireless", *child.Type)
		assert.Nil(t, child.Parent)
	})

	t.Run("an excluded parent does not count", func(t *testing.T) {
		mapper, err := mapping.NewInterfaceMapper(logger, nil, config.InterfaceNameSourceAuto)
		require.NoError(t, err)
		registry := mapping.NewEntityRegistry(logger)
		child := mapInterfaceRow(t, mapper, registry, "2", "radio.if0", "Radio1", "188")
		mapInterfaceRow(t, mapper, registry, "1", "radio", "radio", "188")
		registry.ExcludeInterface("radio")

		registry.ResolveSubinterfaceParents()

		assert.Equal(t, "other-wireless", *child.Type)
		assert.Nil(t, child.Parent)
	})

	t.Run("a colon lane with its port on the device stays a port", func(t *testing.T) {
		mapper, err := mapping.NewInterfaceMapper(logger, nil, config.InterfaceNameSourceAuto)
		require.NoError(t, err)
		registry := mapping.NewEntityRegistry(logger)
		lane := mapInterfaceRow(t, mapper, registry, "2", "1/1/11:1", "lane11-1", "6")
		mapInterfaceRow(t, mapper, registry, "1", "1/1/11", "1/1/11", "6")

		registry.ResolveSubinterfaceParents()

		assert.NotEqual(t, "virtual", *lane.Type)
		assert.Nil(t, lane.Parent)
	})
}
