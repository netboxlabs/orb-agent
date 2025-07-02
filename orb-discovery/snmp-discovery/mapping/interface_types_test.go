package mapping_test

import (
	"testing"

	"github.com/netboxlabs/orb-discovery/snmp-discovery/mapping"
	"github.com/stretchr/testify/assert"
)

var tests = []struct {
	name                 string
	ifType               string
	defaultInterfaceType string
	expectedNetboxType   string
	description          string
	speed                *int64
}{
	// Virtual Interfaces
	{
		name:                 "softwareLoopback",
		ifType:               "24",
		defaultInterfaceType: "",
		expectedNetboxType:   "virtual",
		description:          "softwareLoopback should map to virtual",
	},
	{
		name:                 "propVirtual",
		ifType:               "53",
		defaultInterfaceType: "",
		expectedNetboxType:   "virtual",
		description:          "propVirtual should map to virtual",
	},
	{
		name:                 "virtualIpAddress",
		ifType:               "112",
		defaultInterfaceType: "",
		expectedNetboxType:   "virtual",
		description:          "virtualIpAddress should map to virtual",
	},
	{
		name:                 "tunnel",
		ifType:               "131",
		defaultInterfaceType: "",
		expectedNetboxType:   "virtual",
		description:          "tunnel should map to virtual",
	},
	{
		name:                 "l2vlan",
		ifType:               "135",
		defaultInterfaceType: "",
		expectedNetboxType:   "virtual",
		description:          "l2vlan should map to virtual",
	},
	{
		name:                 "l3ipvlan",
		ifType:               "136",
		defaultInterfaceType: "",
		expectedNetboxType:   "virtual",
		description:          "l3ipvlan should map to virtual",
	},
	{
		name:                 "l3ipxvlan",
		ifType:               "137",
		defaultInterfaceType: "",
		expectedNetboxType:   "virtual",
		description:          "l3ipxvlan should map to virtual",
	},
	{
		name:                 "atmVirtual",
		ifType:               "149",
		defaultInterfaceType: "",
		expectedNetboxType:   "virtual",
		description:          "atmVirtual should map to virtual",
	},
	{
		name:                 "mplsTunnel",
		ifType:               "150",
		defaultInterfaceType: "",
		expectedNetboxType:   "virtual",
		description:          "mplsTunnel should map to virtual",
	},
	{
		name:                 "virtualTg",
		ifType:               "202",
		defaultInterfaceType: "",
		expectedNetboxType:   "virtual",
		description:          "virtualTg should map to virtual",
	},
	{
		name:                 "ciscoISLvlan",
		ifType:               "222",
		defaultInterfaceType: "",
		expectedNetboxType:   "virtual",
		description:          "ciscoISLvlan should map to virtual",
	},
	{
		name:                 "ifPwType",
		ifType:               "246",
		defaultInterfaceType: "",
		expectedNetboxType:   "virtual",
		description:          "ifPwType should map to virtual",
	},
	{
		name:                 "vmwareVirtualNic",
		ifType:               "258",
		defaultInterfaceType: "",
		expectedNetboxType:   "virtual",
		description:          "vmwareVirtualNic should map to virtual",
	},
	{
		name:                 "ifVfiType",
		ifType:               "262",
		defaultInterfaceType: "",
		expectedNetboxType:   "virtual",
		description:          "ifVfiType should map to virtual",
	},
	{
		name:                 "vmwareNicTeam",
		ifType:               "272",
		defaultInterfaceType: "",
		expectedNetboxType:   "virtual",
		description:          "vmwareNicTeam should map to virtual",
	},

	// Bridge and LAG Interfaces
	{
		name:                 "bridge",
		ifType:               "209",
		defaultInterfaceType: "",
		expectedNetboxType:   "bridge",
		description:          "bridge should map to bridge",
	},
	{
		name:                 "ieee8023adLag",
		ifType:               "161",
		defaultInterfaceType: "",
		expectedNetboxType:   "lag",
		description:          "ieee8023adLag should map to lag",
	},

	// Ethernet Interfaces
	{
		name:                 "ethernetCsmacd",
		ifType:               "6",
		defaultInterfaceType: "",
		expectedNetboxType:   "other",
		description:          "ethernetCsmacd should map to other",
	},
	{
		name:                 "iso88023Csmacd",
		ifType:               "7",
		defaultInterfaceType: "",
		expectedNetboxType:   "other",
		description:          "iso88023Csmacd should map to other",
	},
	{
		name:                 "starLan",
		ifType:               "11",
		defaultInterfaceType: "",
		expectedNetboxType:   "other",
		description:          "starLan should map to other",
	},
	{
		name:                 "ethernet3Mbit",
		ifType:               "26",
		defaultInterfaceType: "",
		expectedNetboxType:   "other",
		description:          "ethernet3Mbit should map to other",
	},
	{
		name:                 "ieee80212",
		ifType:               "55",
		defaultInterfaceType: "",
		expectedNetboxType:   "other",
		description:          "ieee80212 should map to other",
	},
	{
		name:                 "fastEther",
		ifType:               "62",
		defaultInterfaceType: "",
		expectedNetboxType:   "other",
		description:          "fastEther should map to other",
	},
	{
		name:                 "fastEtherFX",
		ifType:               "69",
		defaultInterfaceType: "",
		expectedNetboxType:   "other",
		description:          "fastEtherFX should map to other",
	},
	{
		name:                 "gigabitEthernet",
		ifType:               "117",
		defaultInterfaceType: "",
		expectedNetboxType:   "other",
		description:          "gigabitEthernet should map to other",
	},
	{
		name:                 "aviciOpticalEther",
		ifType:               "233",
		defaultInterfaceType: "",
		expectedNetboxType:   "other",
		description:          "aviciOpticalEther should map to other",
	},

	{
		name:                 "ethernetCsmacd with speed",
		ifType:               "6",
		defaultInterfaceType: "",
		expectedNetboxType:   "10gbase-t",
		description:          "ethernetCsmacd should map to 10gbase-t",
		speed:                int64Ptr(10000000),
	},
	{
		name:                 "ethernetCsmacd 10Mbps",
		ifType:               "6",
		defaultInterfaceType: "",
		expectedNetboxType:   "100base-tx",
		description:          "ethernetCsmacd with 10Mbps should map to 100base-tx",
		speed:                int64Ptr(10000),
	},
	{
		name:                 "ethernetCsmacd 100Mbps",
		ifType:               "6",
		defaultInterfaceType: "",
		expectedNetboxType:   "100base-tx",
		description:          "ethernetCsmacd with 100Mbps should map to 100base-tx",
		speed:                int64Ptr(100000),
	},
	{
		name:                 "ethernetCsmacd 1Gbps",
		ifType:               "6",
		defaultInterfaceType: "",
		expectedNetboxType:   "1000base-t",
		description:          "ethernetCsmacd with 1Gbps should map to 1000base-t",
		speed:                int64Ptr(1000000),
	},
	{
		name:                 "ethernetCsmacd 10Gbps",
		ifType:               "6",
		defaultInterfaceType: "",
		expectedNetboxType:   "10gbase-t",
		description:          "ethernetCsmacd with 10Gbps should map to 10gbase-t",
		speed:                int64Ptr(10000000),
	},
	{
		name:                 "ethernetCsmacd 25Gbps",
		ifType:               "6",
		defaultInterfaceType: "",
		expectedNetboxType:   "25gbase-t",
		description:          "ethernetCsmacd with 25Gbps should map to 25gbase-t",
		speed:                int64Ptr(25000000),
	},
	{
		name:                 "ethernetCsmacd 100Gbps",
		ifType:               "6",
		defaultInterfaceType: "",
		expectedNetboxType:   "100gbase-x",
		description:          "ethernetCsmacd with 100Gbps should map to 100gbase-x",
		speed:                int64Ptr(100000000),
	},
	{
		name:                 "ethernetCsmacd 1Mbps",
		ifType:               "6",
		defaultInterfaceType: "",
		expectedNetboxType:   "100base-tx",
		description:          "ethernetCsmacd with 1Mbps should map to 100base-tx",
		speed:                int64Ptr(1000),
	},
	{
		name:                 "ethernetCsmacd 50Mbps",
		ifType:               "6",
		defaultInterfaceType: "",
		expectedNetboxType:   "100base-tx",
		description:          "ethernetCsmacd with 50Mbps should map to 100base-tx",
		speed:                int64Ptr(50000),
	},
	{
		name:                 "ethernetCsmacd 500Mbps",
		ifType:               "6",
		defaultInterfaceType: "",
		expectedNetboxType:   "1000base-t",
		description:          "ethernetCsmacd with 500Mbps should map to 1000base-t",
		speed:                int64Ptr(500000),
	},
	{
		name:                 "ethernetCsmacd 5Gbps",
		ifType:               "6",
		defaultInterfaceType: "",
		expectedNetboxType:   "10gbase-t",
		description:          "ethernetCsmacd with 5Gbps should map to 10gbase-t",
		speed:                int64Ptr(5000000),
	},
	{
		name:                 "ethernetCsmacd 15Gbps",
		ifType:               "6",
		defaultInterfaceType: "",
		expectedNetboxType:   "25gbase-t",
		description:          "ethernetCsmacd with 15Gbps should map to 25gbase-t",
		speed:                int64Ptr(15000000),
	},
	{
		name:                 "ethernetCsmacd 50Gbps",
		ifType:               "6",
		defaultInterfaceType: "",
		expectedNetboxType:   "100gbase-x",
		description:          "ethernetCsmacd with 50Gbps should map to 100gbase-x",
		speed:                int64Ptr(50000000),
	},
	{
		name:                 "ethernetCsmacd 0 speed",
		ifType:               "6",
		defaultInterfaceType: "",
		expectedNetboxType:   "other",
		description:          "ethernetCsmacd with 0 speed should map to other",
		speed:                int64Ptr(0),
	},

	// Tests for other Ethernet interface types with speed
	{
		name:                 "iso88023Csmacd 10Gbps",
		ifType:               "7",
		defaultInterfaceType: "",
		expectedNetboxType:   "10gbase-t",
		description:          "iso88023Csmacd with 10Gbps should map to 10gbase-t",
		speed:                int64Ptr(10000000),
	},
	{
		name:                 "starLan 10Gbps",
		ifType:               "11",
		defaultInterfaceType: "",
		expectedNetboxType:   "10gbase-t",
		description:          "starLan with 10Gbps should map to 10gbase-t",
		speed:                int64Ptr(10000000),
	},
	{
		name:                 "ethernet3Mbit 10Gbps",
		ifType:               "26",
		defaultInterfaceType: "",
		expectedNetboxType:   "10gbase-t",
		description:          "ethernet3Mbit with 10Gbps should map to 10gbase-t",
		speed:                int64Ptr(10000000),
	},
	{
		name:                 "ieee80212 10Gbps",
		ifType:               "55",
		defaultInterfaceType: "",
		expectedNetboxType:   "10gbase-t",
		description:          "ieee80212 with 10Gbps should map to 10gbase-t",
		speed:                int64Ptr(10000000),
	},
	{
		name:                 "fastEther 10Gbps",
		ifType:               "62",
		defaultInterfaceType: "",
		expectedNetboxType:   "10gbase-t",
		description:          "fastEther with 10Gbps should map to 10gbase-t",
		speed:                int64Ptr(10000000),
	},
	{
		name:                 "fastEtherFX 10Gbps",
		ifType:               "69",
		defaultInterfaceType: "",
		expectedNetboxType:   "10gbase-t",
		description:          "fastEtherFX with 10Gbps should map to 10gbase-t",
		speed:                int64Ptr(10000000),
	},
	{
		name:                 "gigabitEthernet 10Gbps",
		ifType:               "117",
		defaultInterfaceType: "",
		expectedNetboxType:   "10gbase-t",
		description:          "gigabitEthernet with 10Gbps should map to 10gbase-t",
		speed:                int64Ptr(10000000),
	},
	{
		name:                 "aviciOpticalEther 10Gbps",
		ifType:               "233",
		defaultInterfaceType: "",
		expectedNetboxType:   "10gbase-t",
		description:          "aviciOpticalEther with 10Gbps should map to 10gbase-t",
		speed:                int64Ptr(10000000),
	},

	// Wireless Interfaces
	{
		name:                 "ieee80211",
		ifType:               "71",
		defaultInterfaceType: "",
		expectedNetboxType:   "ieee802.11n",
		description:          "ieee80211 should map to ieee802.11n",
	},
	{
		name:                 "propWirelessP2P",
		ifType:               "157",
		defaultInterfaceType: "",
		expectedNetboxType:   "other-wireless",
		description:          "propWirelessP2P should map to other-wireless",
	},
	{
		name:                 "propDocsWirelessMaclayer",
		ifType:               "180",
		defaultInterfaceType: "",
		expectedNetboxType:   "other-wireless",
		description:          "propDocsWirelessMaclayer should map to other-wireless",
	},
	{
		name:                 "propDocsWirelessUpstream",
		ifType:               "181",
		defaultInterfaceType: "",
		expectedNetboxType:   "other-wireless",
		description:          "propDocsWirelessUpstream should map to other-wireless",
	},
	{
		name:                 "hiperlan2",
		ifType:               "183",
		defaultInterfaceType: "",
		expectedNetboxType:   "other-wireless",
		description:          "hiperlan2 should map to other-wireless",
	},
	{
		name:                 "propBWAp2Mp",
		ifType:               "184",
		defaultInterfaceType: "",
		expectedNetboxType:   "other-wireless",
		description:          "propBWAp2Mp should map to other-wireless",
	},
	{
		name:                 "radioMAC",
		ifType:               "188",
		defaultInterfaceType: "",
		expectedNetboxType:   "other-wireless",
		description:          "radioMAC should map to other-wireless",
	},
	{
		name:                 "atmRadio",
		ifType:               "189",
		defaultInterfaceType: "",
		expectedNetboxType:   "other-wireless",
		description:          "atmRadio should map to other-wireless",
	},
	{
		name:                 "ieee80216WMAN",
		ifType:               "237",
		defaultInterfaceType: "",
		expectedNetboxType:   "other-wireless",
		description:          "ieee80216WMAN should map to other-wireless",
	},
	{
		name:                 "capwapDot11Profile",
		ifType:               "252",
		defaultInterfaceType: "",
		expectedNetboxType:   "other-wireless",
		description:          "capwapDot11Profile should map to other-wireless",
	},
	{
		name:                 "capwapDot11Bss",
		ifType:               "253",
		defaultInterfaceType: "",
		expectedNetboxType:   "other-wireless",
		description:          "capwapDot11Bss should map to other-wireless",
	},
	{
		name:                 "capwapWtpVirtualRadio",
		ifType:               "254",
		defaultInterfaceType: "",
		expectedNetboxType:   "other-wireless",
		description:          "capwapWtpVirtualRadio should map to other-wireless",
	},
	{
		name:                 "ieee802154",
		ifType:               "259",
		defaultInterfaceType: "",
		expectedNetboxType:   "ieee802.15.4",
		description:          "ieee802154 should map to ieee802.15.4",
	},
	{
		name:                 "xboxWireless",
		ifType:               "281",
		defaultInterfaceType: "",
		expectedNetboxType:   "other-wireless",
		description:          "xboxWireless should map to other-wireless",
	},

	// Cellular Interfaces
	{
		name:                 "wwanPP",
		ifType:               "243",
		defaultInterfaceType: "",
		expectedNetboxType:   "4g",
		description:          "wwanPP should map to 4g",
	},
	{
		name:                 "wwanPP2",
		ifType:               "244",
		defaultInterfaceType: "",
		expectedNetboxType:   "4g",
		description:          "wwanPP2 should map to 4g",
	},
	{
		name:                 "cpri",
		ifType:               "300",
		defaultInterfaceType: "",
		expectedNetboxType:   "4g",
		description:          "cpri should map to 4g",
	},

	// SONET/SDH Interfaces
	{
		name:                 "sonet",
		ifType:               "39",
		defaultInterfaceType: "",
		expectedNetboxType:   "sonet-oc3",
		description:          "sonet should map to sonet-oc3",
	},
	{
		name:                 "sonetPath",
		ifType:               "50",
		defaultInterfaceType: "",
		expectedNetboxType:   "sonet-oc3",
		description:          "sonetPath should map to sonet-oc3",
	},
	{
		name:                 "sonetVT",
		ifType:               "51",
		defaultInterfaceType: "",
		expectedNetboxType:   "sonet-oc3",
		description:          "sonetVT should map to sonet-oc3",
	},
	{
		name:                 "pos",
		ifType:               "171",
		defaultInterfaceType: "",
		expectedNetboxType:   "sonet-oc3",
		description:          "pos should map to sonet-oc3",
	},
	{
		name:                 "sonetOverheadChannel",
		ifType:               "185",
		defaultInterfaceType: "",
		expectedNetboxType:   "sonet-oc3",
		description:          "sonetOverheadChannel should map to sonet-oc3",
	},

	// Fibre Channel Interfaces
	{
		name:                 "fibreChannel",
		ifType:               "56",
		defaultInterfaceType: "",
		expectedNetboxType:   "1gfc-sfp",
		description:          "fibreChannel should map to 1gfc-sfp",
	},
	{
		name:                 "fcipLink",
		ifType:               "224",
		defaultInterfaceType: "",
		expectedNetboxType:   "1gfc-sfp",
		description:          "fcipLink should map to 1gfc-sfp",
	},

	// InfiniBand Interfaces
	{
		name:                 "infiniband",
		ifType:               "199",
		defaultInterfaceType: "",
		expectedNetboxType:   "infiniband-sdr",
		description:          "infiniband should map to infiniband-sdr",
	},

	// Serial Interfaces
	{
		name:                 "ds1",
		ifType:               "18",
		defaultInterfaceType: "",
		expectedNetboxType:   "t1",
		description:          "ds1 should map to t1",
	},
	{
		name:                 "e1",
		ifType:               "19",
		defaultInterfaceType: "",
		expectedNetboxType:   "e1",
		description:          "e1 should map to e1",
	},
	{
		name:                 "ds3",
		ifType:               "30",
		defaultInterfaceType: "",
		expectedNetboxType:   "t3",
		description:          "ds3 should map to t3",
	},
	{
		name:                 "propPointToPointSerial",
		ifType:               "22",
		defaultInterfaceType: "",
		expectedNetboxType:   "t1",
		description:          "propPointToPointSerial should map to t1",
	},
	{
		name:                 "rs232",
		ifType:               "33",
		defaultInterfaceType: "",
		expectedNetboxType:   "t1",
		description:          "rs232 should map to t1",
	},
	{
		name:                 "v11",
		ifType:               "64",
		defaultInterfaceType: "",
		expectedNetboxType:   "t1",
		description:          "v11 should map to t1",
	},
	{
		name:                 "v36",
		ifType:               "65",
		defaultInterfaceType: "",
		expectedNetboxType:   "t1",
		description:          "v36 should map to t1",
	},
	{
		name:                 "g703at64k",
		ifType:               "66",
		defaultInterfaceType: "",
		expectedNetboxType:   "t1",
		description:          "g703at64k should map to t1",
	},
	{
		name:                 "g703at2mb",
		ifType:               "67",
		defaultInterfaceType: "",
		expectedNetboxType:   "t1",
		description:          "g703at2mb should map to t1",
	},
	{
		name:                 "ds0",
		ifType:               "81",
		defaultInterfaceType: "",
		expectedNetboxType:   "t1",
		description:          "ds0 should map to t1",
	},
	{
		name:                 "ds0Bundle",
		ifType:               "82",
		defaultInterfaceType: "",
		expectedNetboxType:   "t1",
		description:          "ds0Bundle should map to t1",
	},
	{
		name:                 "ds1FDL",
		ifType:               "170",
		defaultInterfaceType: "",
		expectedNetboxType:   "t1",
		description:          "ds1FDL should map to t1",
	},

	// ATM/DSL Interfaces
	{
		name:                 "atm",
		ifType:               "37",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "atm should map to xdsl",
	},
	{
		name:                 "aal5",
		ifType:               "49",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "aal5 should map to xdsl",
	},
	{
		name:                 "atmLogical",
		ifType:               "80",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "atmLogical should map to xdsl",
	},
	{
		name:                 "atmDxi",
		ifType:               "105",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "atmDxi should map to xdsl",
	},
	{
		name:                 "atmFuni",
		ifType:               "106",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "atmFuni should map to xdsl",
	},
	{
		name:                 "atmIma",
		ifType:               "107",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "atmIma should map to xdsl",
	},
	{
		name:                 "ipOverAtm",
		ifType:               "114",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "ipOverAtm should map to xdsl",
	},
	{
		name:                 "atmSubInterface",
		ifType:               "134",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "atmSubInterface should map to xdsl",
	},
	{
		name:                 "voiceOverAtm",
		ifType:               "152",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "voiceOverAtm should map to xdsl",
	},
	{
		name:                 "aal2",
		ifType:               "187",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "aal2 should map to xdsl",
	},
	{
		name:                 "propAtm",
		ifType:               "197",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "propAtm should map to xdsl",
	},
	{
		name:                 "atmbond",
		ifType:               "234",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "atmbond should map to xdsl",
	},
	{
		name:                 "adsl",
		ifType:               "94",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "adsl should map to xdsl",
	},
	{
		name:                 "radsl",
		ifType:               "95",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "radsl should map to xdsl",
	},
	{
		name:                 "sdsl",
		ifType:               "96",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "sdsl should map to xdsl",
	},
	{
		name:                 "vdsl",
		ifType:               "97",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "vdsl should map to xdsl",
	},
	{
		name:                 "msdsl",
		ifType:               "143",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "msdsl should map to xdsl",
	},
	{
		name:                 "idsl",
		ifType:               "154",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "idsl should map to xdsl",
	},
	{
		name:                 "hdsl2",
		ifType:               "168",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "hdsl2 should map to xdsl",
	},
	{
		name:                 "shdsl",
		ifType:               "169",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "shdsl should map to xdsl",
	},
	{
		name:                 "mvl",
		ifType:               "191",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "mvl should map to xdsl",
	},
	{
		name:                 "reachDSL",
		ifType:               "192",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "reachDSL should map to xdsl",
	},
	{
		name:                 "adsl2",
		ifType:               "230",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "adsl2 should map to xdsl",
	},
	{
		name:                 "adsl2plus",
		ifType:               "238",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "adsl2plus should map to xdsl",
	},
	{
		name:                 "vdsl2",
		ifType:               "251",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "vdsl2 should map to xdsl",
	},
	{
		name:                 "gfast",
		ifType:               "279",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "gfast should map to xdsl",
	},
	{
		name:                 "fastdsl",
		ifType:               "282",
		defaultInterfaceType: "",
		expectedNetboxType:   "xdsl",
		description:          "fastdsl should map to xdsl",
	},

	// Coaxial Interfaces
	{
		name:                 "docsCableMaclayer",
		ifType:               "127",
		defaultInterfaceType: "",
		expectedNetboxType:   "docsis",
		description:          "docsCableMaclayer should map to docsis",
	},
	{
		name:                 "docsCableDownstream",
		ifType:               "128",
		defaultInterfaceType: "",
		expectedNetboxType:   "docsis",
		description:          "docsCableDownstream should map to docsis",
	},
	{
		name:                 "docsCableUpstream",
		ifType:               "129",
		defaultInterfaceType: "",
		expectedNetboxType:   "docsis",
		description:          "docsCableUpstream should map to docsis",
	},
	{
		name:                 "docsCableUpstreamChannel",
		ifType:               "205",
		defaultInterfaceType: "",
		expectedNetboxType:   "docsis",
		description:          "docsCableUpstreamChannel should map to docsis",
	},
	{
		name:                 "docsCableMCmtsDownstream",
		ifType:               "229",
		defaultInterfaceType: "",
		expectedNetboxType:   "docsis",
		description:          "docsCableMCmtsDownstream should map to docsis",
	},
	{
		name:                 "docsCableUpstreamRfPort",
		ifType:               "256",
		defaultInterfaceType: "",
		expectedNetboxType:   "docsis",
		description:          "docsCableUpstreamRfPort should map to docsis",
	},
	{
		name:                 "cableDownstreamRfPort",
		ifType:               "257",
		defaultInterfaceType: "",
		expectedNetboxType:   "docsis",
		description:          "cableDownstreamRfPort should map to docsis",
	},
	{
		name:                 "docsOfdmDownstream",
		ifType:               "277",
		defaultInterfaceType: "",
		expectedNetboxType:   "docsis",
		description:          "docsOfdmDownstream should map to docsis",
	},
	{
		name:                 "docsOfdmaUpstream",
		ifType:               "278",
		defaultInterfaceType: "",
		expectedNetboxType:   "docsis",
		description:          "docsOfdmaUpstream should map to docsis",
	},
	{
		name:                 "docsCableScte55d1FwdOob",
		ifType:               "283",
		defaultInterfaceType: "",
		expectedNetboxType:   "docsis",
		description:          "docsCableScte55d1FwdOob should map to docsis",
	},
	{
		name:                 "docsCableScte55d1RetOob",
		ifType:               "284",
		defaultInterfaceType: "",
		expectedNetboxType:   "docsis",
		description:          "docsCableScte55d1RetOob should map to docsis",
	},
	{
		name:                 "docsCableScte55d2DsOob",
		ifType:               "285",
		defaultInterfaceType: "",
		expectedNetboxType:   "docsis",
		description:          "docsCableScte55d2DsOob should map to docsis",
	},
	{
		name:                 "docsCableScte55d2UsOob",
		ifType:               "286",
		defaultInterfaceType: "",
		expectedNetboxType:   "docsis",
		description:          "docsCableScte55d2UsOob should map to docsis",
	},
	{
		name:                 "docsCableNdf",
		ifType:               "287",
		defaultInterfaceType: "",
		expectedNetboxType:   "docsis",
		description:          "docsCableNdf should map to docsis",
	},
	{
		name:                 "docsCableNdr",
		ifType:               "288",
		defaultInterfaceType: "",
		expectedNetboxType:   "docsis",
		description:          "docsCableNdr should map to docsis",
	},

	// MoCA Interface
	{
		name:                 "mocaVersion1",
		ifType:               "236",
		defaultInterfaceType: "",
		expectedNetboxType:   "moca",
		description:          "mocaVersion1 should map to moca",
	},

	// PON Interfaces
	{
		name:                 "pon155",
		ifType:               "207",
		defaultInterfaceType: "",
		expectedNetboxType:   "bpon",
		description:          "pon155 should map to bpon",
	},
	{
		name:                 "pon622",
		ifType:               "208",
		defaultInterfaceType: "",
		expectedNetboxType:   "bpon",
		description:          "pon622 should map to bpon",
	},
	{
		name:                 "gpon",
		ifType:               "250",
		defaultInterfaceType: "",
		expectedNetboxType:   "gpon",
		description:          "gpon should map to gpon",
	},
	{
		name:                 "aluEpon",
		ifType:               "266",
		defaultInterfaceType: "",
		expectedNetboxType:   "epon",
		description:          "aluEpon should map to epon",
	},
	{
		name:                 "aluEponOnu",
		ifType:               "267",
		defaultInterfaceType: "",
		expectedNetboxType:   "epon",
		description:          "aluEponOnu should map to epon",
	},
	{
		name:                 "aluEponPhysicalUni",
		ifType:               "268",
		defaultInterfaceType: "",
		expectedNetboxType:   "epon",
		description:          "aluEponPhysicalUni should map to epon",
	},
	{
		name:                 "aluEponLogicalLink",
		ifType:               "269",
		defaultInterfaceType: "",
		expectedNetboxType:   "epon",
		description:          "aluEponLogicalLink should map to epon",
	},
	{
		name:                 "aluGponOnu",
		ifType:               "270",
		defaultInterfaceType: "",
		expectedNetboxType:   "gpon",
		description:          "aluGponOnu should map to gpon",
	},
	{
		name:                 "aluGponPhysicalUni",
		ifType:               "271",
		defaultInterfaceType: "",
		expectedNetboxType:   "gpon",
		description:          "aluGponPhysicalUni should map to gpon",
	},

	// Stacking Interfaces
	{
		name:                 "stackToStack",
		ifType:               "111",
		defaultInterfaceType: "",
		expectedNetboxType:   "cisco-stackwise",
		description:          "stackToStack should map to cisco-stackwise",
	},

	// Edge cases
	{
		name:                 "unknown ifType with empty default",
		ifType:               "999",
		defaultInterfaceType: "",
		expectedNetboxType:   "other",
		description:          "unknown ifType should return other when default is empty",
	},
	{
		name:                 "unknown ifType with custom default",
		ifType:               "999",
		defaultInterfaceType: "custom-type",
		expectedNetboxType:   "custom-type",
		description:          "unknown ifType should return custom default when provided",
	},
	{
		name:                 "zero ifType with empty default",
		ifType:               "0",
		defaultInterfaceType: "",
		expectedNetboxType:   "other",
		description:          "zero ifType should return other when default is empty",
	},
	{
		name:                 "negative ifType with empty default",
		ifType:               "-1",
		defaultInterfaceType: "",
		expectedNetboxType:   "other",
		description:          "negative ifType should return other when default is empty",
	},
}

func TestGetNetboxType(t *testing.T) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapping.GetNetboxType(tt.ifType, tt.defaultInterfaceType, tt.speed)
			assert.Equal(t, tt.expectedNetboxType, result, tt.description)
		})
	}
}

func TestInterfaceTypeMap_Completeness(t *testing.T) {
	// Test that all interface types in the map are covered by our tests
	// This helps ensure we don't miss any mappings when the map is updated

	// Get all ifType values from the map
	var ifTypes []string
	for ifType := range mapping.InterfaceTypeMap {
		ifTypes = append(ifTypes, ifType)
	}

	// Create a map of tested ifTypes for quick lookup
	testedIfTypes := make(map[string]bool)
	for _, test := range tests {
		testedIfTypes[test.ifType] = true
	}

	// Verify we have tests for all ifType values
	for _, ifType := range ifTypes {
		assert.True(t, testedIfTypes[ifType], "Missing test for ifType %s", ifType)
	}
}
