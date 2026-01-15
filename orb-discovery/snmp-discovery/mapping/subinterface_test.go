package mapping_test

import (
	"log/slog"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/mapping"
	"github.com/stretchr/testify/assert"
)

func TestExtractParentInterfaceName(t *testing.T) {
	tests := []struct {
		name           string
		interfaceName  string
		expectedParent string
		description    string
	}{
		// Dot separator tests (Cisco, Juniper, Arista, Nokia style)
		{
			name:           "Simple subinterface with dot",
			interfaceName:  "eth0.100",
			expectedParent: "eth0",
			description:    "eth0.100 should extract parent eth0",
		},
		{
			name:           "Cisco GigabitEthernet subinterface",
			interfaceName:  "GigabitEthernet0/0.100",
			expectedParent: "GigabitEthernet0/0",
			description:    "GigabitEthernet0/0.100 should extract parent GigabitEthernet0/0",
		},
		{
			name:           "Cisco TenGigabitEthernet subinterface",
			interfaceName:  "TenGigabitEthernet1/1/1.200",
			expectedParent: "TenGigabitEthernet1/1/1",
			description:    "TenGigabitEthernet1/1/1.200 should extract parent TenGigabitEthernet1/1/1",
		},
		{
			name:           "Juniper ge subinterface",
			interfaceName:  "ge-0/0/0.0",
			expectedParent: "ge-0/0/0",
			description:    "ge-0/0/0.0 should extract parent ge-0/0/0",
		},
		{
			name:           "Juniper xe subinterface",
			interfaceName:  "xe-1/2/3.100",
			expectedParent: "xe-1/2/3",
			description:    "xe-1/2/3.100 should extract parent xe-1/2/3",
		},
		{
			name:           "Juniper ae subinterface",
			interfaceName:  "ae0.100",
			expectedParent: "ae0",
			description:    "ae0.100 should extract parent ae0",
		},
		{
			name:           "Arista Ethernet subinterface",
			interfaceName:  "Ethernet1/1.100",
			expectedParent: "Ethernet1/1",
			description:    "Ethernet1/1.100 should extract parent Ethernet1/1",
		},
		{
			name:           "Nokia port subinterface",
			interfaceName:  "1/1/1.100",
			expectedParent: "1/1/1",
			description:    "1/1/1.100 should extract parent 1/1/1",
		},
		{
			name:           "Cisco Port-channel subinterface",
			interfaceName:  "Port-channel1.100",
			expectedParent: "Port-channel1",
			description:    "Port-channel1.100 should extract parent Port-channel1",
		},
		{
			name:           "Multiple dot separators",
			interfaceName:  "eth0.100.200",
			expectedParent: "eth0.100",
			description:    "eth0.100.200 should extract rightmost parent eth0.100",
		},

		// Colon separator tests (Juniper style, legacy)
		{
			name:           "Juniper colon style subinterface",
			interfaceName:  "ge-0/0/0:0",
			expectedParent: "ge-0/0/0",
			description:    "ge-0/0/0:0 should extract parent ge-0/0/0",
		},
		{
			name:           "Simple colon subinterface",
			interfaceName:  "eth0:1",
			expectedParent: "eth0",
			description:    "eth0:1 should extract parent eth0",
		},
		{
			name:           "Multiple colon separators",
			interfaceName:  "eth0:1:2",
			expectedParent: "eth0:1",
			description:    "eth0:1:2 should extract rightmost parent eth0:1",
		},

		// Non-subinterface tests (should return empty string)
		{
			name:           "Physical interface without separator",
			interfaceName:  "eth0",
			expectedParent: "",
			description:    "eth0 should return empty string (not a subinterface)",
		},
		{
			name:           "GigabitEthernet without subinterface",
			interfaceName:  "GigabitEthernet0/0/1",
			expectedParent: "",
			description:    "GigabitEthernet0/0/1 should return empty string (slashes are not separators)",
		},
		{
			name:           "Juniper physical interface",
			interfaceName:  "ge-0/0/0",
			expectedParent: "",
			description:    "ge-0/0/0 should return empty string (not a subinterface)",
		},
		{
			name:           "Management interface",
			interfaceName:  "mgmt0",
			expectedParent: "",
			description:    "mgmt0 should return empty string (not a subinterface)",
		},
		{
			name:           "Loopback interface",
			interfaceName:  "Loopback0",
			expectedParent: "",
			description:    "Loopback0 should return empty string (not a subinterface)",
		},
		{
			name:           "VLAN interface",
			interfaceName:  "Vlan100",
			expectedParent: "",
			description:    "Vlan100 should return empty string (not a subinterface)",
		},

		// Edge cases
		{
			name:           "Empty interface name",
			interfaceName:  "",
			expectedParent: "",
			description:    "Empty string should return empty string",
		},
		{
			name:           "Dot at beginning",
			interfaceName:  ".100",
			expectedParent: "",
			description:    ".100 should return empty string (no parent part)",
		},
		{
			name:           "Dot at end",
			interfaceName:  "eth0.",
			expectedParent: "",
			description:    "eth0. should return empty string (no child part)",
		},
		{
			name:           "Colon at beginning",
			interfaceName:  ":100",
			expectedParent: "",
			description:    ":100 should return empty string (no parent part)",
		},
		{
			name:           "Colon at end",
			interfaceName:  "eth0:",
			expectedParent: "",
			description:    "eth0: should return empty string (no child part)",
		},
		{
			name:           "Single dot",
			interfaceName:  ".",
			expectedParent: "",
			description:    ". should return empty string",
		},
		{
			name:           "Single colon",
			interfaceName:  ":",
			expectedParent: "",
			description:    ": should return empty string",
		},
		{
			name:           "Mixed separators dot then colon",
			interfaceName:  "eth0.100:1",
			expectedParent: "eth0",
			description:    "eth0.100:1 should extract parent eth0 (dot has priority)",
		},
		{
			name:           "Mixed separators colon then dot",
			interfaceName:  "eth0:1.100",
			expectedParent: "eth0:1",
			description:    "eth0:1.100 should extract parent eth0:1 (dot found first)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapping.ExtractParentInterfaceName(tt.interfaceName)
			assert.Equal(t, tt.expectedParent, result, tt.description)
		})
	}
}

func TestResolveInterfaceType_Subinterfaces(t *testing.T) {
	tests := []struct {
		name                 string
		interfaceName        string
		ifType               string
		speed                *int64
		defaultInterfaceType string
		expectedType         string
		description          string
	}{
		// Subinterfaces should always return "virtual" (Tier 0 - highest priority)
		{
			name:                 "Simple subinterface with dot",
			interfaceName:        "eth0.100",
			ifType:               "6", // ethernetCsmacd
			speed:                int64Ptr(1000000),
			defaultInterfaceType: "",
			expectedType:         "virtual",
			description:          "eth0.100 should be virtual regardless of ifType or speed",
		},
		{
			name:                 "Cisco subinterface with gigabit speed",
			interfaceName:        "GigabitEthernet0/0.100",
			ifType:               "6", // ethernetCsmacd
			speed:                int64Ptr(1000000),
			defaultInterfaceType: "",
			expectedType:         "virtual",
			description:          "GigabitEthernet0/0.100 should be virtual even with gigabit speed",
		},
		{
			name:                 "Juniper subinterface with colon",
			interfaceName:        "ge-0/0/0:0",
			ifType:               "6",
			speed:                int64Ptr(1000000),
			defaultInterfaceType: "",
			expectedType:         "virtual",
			description:          "ge-0/0/0:0 should be virtual with colon separator",
		},
		{
			name:                 "Subinterface with LAG ifType",
			interfaceName:        "Port-channel1.100",
			ifType:               "161", // ieee8023adLag
			speed:                nil,
			defaultInterfaceType: "",
			expectedType:         "virtual",
			description:          "Port-channel1.100 should be virtual, not lag",
		},
		{
			name:                 "Subinterface with tunnel ifType",
			interfaceName:        "Tunnel0.100",
			ifType:               "131", // tunnel
			speed:                nil,
			defaultInterfaceType: "",
			expectedType:         "virtual",
			description:          "Tunnel0.100 should be virtual",
		},
		{
			name:                 "Subinterface with custom default",
			interfaceName:        "eth0.100",
			ifType:               "6",
			speed:                nil,
			defaultInterfaceType: "custom-type",
			expectedType:         "virtual",
			description:          "eth0.100 should be virtual, ignoring custom default",
		},
		{
			name:                 "Multiple level subinterface",
			interfaceName:        "eth0.100.200",
			ifType:               "6",
			speed:                int64Ptr(10000000),
			defaultInterfaceType: "",
			expectedType:         "virtual",
			description:          "eth0.100.200 should be virtual (multi-level subinterface)",
		},

		// Non-subinterfaces should follow normal resolution rules
		{
			name:                 "Physical interface with ethernet type",
			interfaceName:        "eth0",
			ifType:               "6",
			speed:                int64Ptr(1000000),
			defaultInterfaceType: "",
			expectedType:         "1000base-t",
			description:          "eth0 should resolve to 1000base-t based on speed",
		},
		{
			name:                 "Physical GigabitEthernet",
			interfaceName:        "GigabitEthernet0/0/1",
			ifType:               "6",
			speed:                int64Ptr(1000000),
			defaultInterfaceType: "",
			expectedType:         "1000base-t",
			description:          "GigabitEthernet0/0/1 should resolve based on speed (slashes are OK)",
		},
		{
			name:                 "Loopback interface",
			interfaceName:        "Loopback0",
			ifType:               "24", // softwareLoopback
			speed:                nil,
			defaultInterfaceType: "",
			expectedType:         "virtual",
			description:          "Loopback0 should be virtual based on ifType (not subinterface detection)",
		},
		{
			name:                 "VLAN interface without dot",
			interfaceName:        "Vlan100",
			ifType:               "136", // l3ipvlan
			speed:                nil,
			defaultInterfaceType: "",
			expectedType:         "virtual",
			description:          "Vlan100 should be virtual based on ifType (not subinterface detection)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapping.ResolveInterfaceType(
				tt.interfaceName,
				tt.ifType,
				tt.speed,
				tt.defaultInterfaceType,
				nil, // patternMatcher
				0,   // userPatternCount
			)
			assert.Equal(t, tt.expectedType, result, tt.description)
		})
	}
}

func TestGetInterfaceByName(t *testing.T) {
	// This test verifies the GetInterfaceByName method works correctly
	// which is critical for parent interface resolution
	logger := slog.Default()
	registry := mapping.NewEntityRegistry(logger)

	// Create some test interfaces with realistic SNMP indices
	eth0Name := "eth0"
	eth0Type := "1000base-t"
	eth0 := registry.GetOrCreateEntity(mapping.InterfaceEntityType, mapping.ObjectIDIndex("100"))
	if iface, ok := eth0.(*diode.Interface); ok {
		iface.Name = &eth0Name
		iface.Type = &eth0Type
	}

	eth0Sub100Name := "eth0.100"
	eth0Sub100Type := "virtual"
	eth0Sub100 := registry.GetOrCreateEntity(mapping.InterfaceEntityType, mapping.ObjectIDIndex("200"))
	if iface, ok := eth0Sub100.(*diode.Interface); ok {
		iface.Name = &eth0Sub100Name
		iface.Type = &eth0Sub100Type
	}

	ge000Name := "ge-0/0/0"
	ge000Type := "1000base-t"
	ge000 := registry.GetOrCreateEntity(mapping.InterfaceEntityType, mapping.ObjectIDIndex("300"))
	if iface, ok := ge000.(*diode.Interface); ok {
		iface.Name = &ge000Name
		iface.Type = &ge000Type
	}

	tests := []struct {
		name         string
		searchName   string
		shouldFind   bool
		expectedType string
		description  string
	}{
		{
			name:         "Find eth0 by name",
			searchName:   "eth0",
			shouldFind:   true,
			expectedType: "1000base-t",
			description:  "Should find eth0 interface",
		},
		{
			name:         "Find eth0.100 by name",
			searchName:   "eth0.100",
			shouldFind:   true,
			expectedType: "virtual",
			description:  "Should find eth0.100 subinterface",
		},
		{
			name:         "Find ge-0/0/0 by name",
			searchName:   "ge-0/0/0",
			shouldFind:   true,
			expectedType: "1000base-t",
			description:  "Should find Juniper interface",
		},
		{
			name:        "Non-existent interface",
			searchName:  "eth1",
			shouldFind:  false,
			description: "Should not find non-existent interface",
		},
		{
			name:        "Empty string",
			searchName:  "",
			shouldFind:  false,
			description: "Should not find with empty string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := registry.GetInterfaceByName(tt.searchName)
			if tt.shouldFind {
				assert.NotNil(t, result, tt.description)
				if result != nil {
					assert.NotNil(t, result.Name, "Interface name should not be nil")
					assert.Equal(t, tt.searchName, *result.Name, "Interface name should match")
					assert.NotNil(t, result.Type, "Interface type should not be nil")
					assert.Equal(t, tt.expectedType, *result.Type, "Interface type should match")
				}
			} else {
				assert.Nil(t, result, tt.description)
			}
		})
	}
}

func TestResolveSubinterfaceParents(t *testing.T) {
	// This test verifies that parent resolution works correctly
	// even when subinterfaces are discovered before their parent interfaces
	logger := slog.Default()
	registry := mapping.NewEntityRegistry(logger)

	// Simulate the common case where subinterface is discovered BEFORE parent
	// (This is the issue we're solving with post-processing)

	// 1. Create subinterface FIRST (as would happen with some SNMP discoveries)
	subName := "GigabitEthernet0/0.100"
	subType := "virtual"
	subInterface := registry.GetOrCreateEntity(mapping.InterfaceEntityType, mapping.ObjectIDIndex("200"))
	if iface, ok := subInterface.(*diode.Interface); ok {
		iface.Name = &subName
		iface.Type = &subType
	}

	// 2. Create another subinterface (also before parent)
	sub2Name := "GigabitEthernet0/0.200"
	sub2Type := "virtual"
	sub2Interface := registry.GetOrCreateEntity(mapping.InterfaceEntityType, mapping.ObjectIDIndex("300"))
	if iface, ok := sub2Interface.(*diode.Interface); ok {
		iface.Name = &sub2Name
		iface.Type = &sub2Type
	}

	// 3. Create parent interface LAST (as would happen in real discovery)
	parentName := "GigabitEthernet0/0"
	parentType := "1000base-t"
	parentInterface := registry.GetOrCreateEntity(mapping.InterfaceEntityType, mapping.ObjectIDIndex("100"))
	if iface, ok := parentInterface.(*diode.Interface); ok {
		iface.Name = &parentName
		iface.Type = &parentType
	}

	// 4. Create a Juniper subinterface with colon separator
	juniperSubName := "ge-0/0/0:0"
	juniperSubType := "virtual"
	juniperSubInterface := registry.GetOrCreateEntity(mapping.InterfaceEntityType, mapping.ObjectIDIndex("400"))
	if iface, ok := juniperSubInterface.(*diode.Interface); ok {
		iface.Name = &juniperSubName
		iface.Type = &juniperSubType
	}

	// 5. Create Juniper parent
	juniperParentName := "ge-0/0/0"
	juniperParentType := "1000base-t"
	juniperParent := registry.GetOrCreateEntity(mapping.InterfaceEntityType, mapping.ObjectIDIndex("500"))
	if iface, ok := juniperParent.(*diode.Interface); ok {
		iface.Name = &juniperParentName
		iface.Type = &juniperParentType
	}

	// 6. Create an orphan subinterface (parent doesn't exist)
	orphanName := "eth1.100"
	orphanType := "virtual"
	orphanInterface := registry.GetOrCreateEntity(mapping.InterfaceEntityType, mapping.ObjectIDIndex("600"))
	if iface, ok := orphanInterface.(*diode.Interface); ok {
		iface.Name = &orphanName
		iface.Type = &orphanType
	}

	// At this point, no parent references should be set yet
	sub := subInterface.(*diode.Interface)
	assert.Nil(t, sub.Parent, "Parent should be nil before resolution")

	// Now call the post-processing method
	registry.ResolveSubinterfaceParents()

	// Verify all subinterfaces now have correct parent references
	sub = subInterface.(*diode.Interface)
	assert.NotNil(t, sub.Parent, "Parent should be resolved after post-processing")
	assert.Equal(t, parentName, *sub.Parent.Name)
	assert.Equal(t, parentType, *sub.Parent.Type)

	sub2 := sub2Interface.(*diode.Interface)
	assert.NotNil(t, sub2.Parent, "Second subinterface should also have parent")
	assert.Equal(t, parentName, *sub2.Parent.Name)

	juniperSub := juniperSubInterface.(*diode.Interface)
	assert.NotNil(t, juniperSub.Parent, "Juniper subinterface should have parent")
	assert.Equal(t, juniperParentName, *juniperSub.Parent.Name)

	// Orphan should have no parent (parent wasn't discovered)
	orphan := orphanInterface.(*diode.Interface)
	assert.Nil(t, orphan.Parent, "Orphan subinterface should have no parent")

	// Physical interfaces should have no parent
	parent := parentInterface.(*diode.Interface)
	assert.Nil(t, parent.Parent, "Physical interface should have no parent")
}
