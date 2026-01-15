package mapping

import "github.com/netboxlabs/orb-discovery/snmp-discovery/config"

// DefaultInterfacePatterns provides vendor-agnostic interface type detection
// Covers 80-90% of common deployments across major vendors
// Ordered by specificity (most specific first within each vendor)
var DefaultInterfacePatterns = []config.InterfacePattern{
	// Cisco IOS/IOS-XE - High-Speed Interfaces
	{Match: `^(HundredGig|Hu)\S+`, Type: "100gbase-x-qsfp28"},
	{Match: `^(FortyGig|Fo)\S+`, Type: "40gbase-x-qsfpp"},
	{Match: `^(TwentyFiveGig|Twe)\S+`, Type: "25gbase-x-sfp28"},
	{Match: `^(TenGig|Te)\S+`, Type: "10gbase-x-sfpp"},
	{Match: `^(FiveGig|Fi)\S+`, Type: "5gbase-t"},
	{Match: `^(TwoGig|Tw)\S+`, Type: "2.5gbase-t"},

	// Cisco IOS/IOS-XE - Standard Interfaces
	{Match: `^(GigabitEthernet|Gi)\d+`, Type: "1000base-t"},
	{Match: `^(FastEthernet|Fa)\d+`, Type: "100base-tx"},

	// Juniper JunOS - Physical Interfaces
	{Match: `^et-\d+/\d+/\d+`, Type: "40gbase-x-qsfpp"}, // Can be 40G or 100G
	{Match: `^xe-\d+/\d+/\d+`, Type: "10gbase-x-sfpp"},
	{Match: `^ge-\d+/\d+/\d+`, Type: "1000base-t"},

	// Nokia SR OS
	{Match: `^ethernet-\d+/\d+`, Type: "1000base-t"},

	// LAG/Port-Channel (Cross-vendor)
	{Match: `^(Port-channel|port-channel|Po)\d+`, Type: "lag"},
	{Match: `^ae\d+`, Type: "lag"},           // Juniper
	{Match: `^Bundle-Ether\d+`, Type: "lag"}, // Cisco IOS-XR

	// Loopback Interfaces (Virtual)
	{Match: `^Loopback\d+`, Type: "virtual"}, // Cisco/Arista
	{Match: `^lo\d*$`, Type: "virtual"},      // Juniper/Linux

	// VLAN/SVI Interfaces (Virtual)
	{Match: `^Vlan\d+`, Type: "virtual"},   // Cisco/Arista
	{Match: `^vlan\.\d+`, Type: "virtual"}, // Juniper
	{Match: `^irb$`, Type: "virtual"},      // Juniper IRB

	// Tunnel Interfaces (Virtual)
	{Match: `^Tunnel\d+`, Type: "virtual"}, // Cisco

	// Management Interfaces
	{Match: `^(Management|mgmt)\d+`, Type: "1000base-t"}, // Cisco/Arista
	{Match: `^(fxp|em)\d+`, Type: "1000base-t"},          // Juniper

	// Cumulus Linux Switch Ports
	{Match: `^swp\d+`, Type: "1000base-t"},

	// Generic Linux Ethernet
	{Match: `^(eth|ens|enp)\d+`, Type: "1000base-t"},
}
