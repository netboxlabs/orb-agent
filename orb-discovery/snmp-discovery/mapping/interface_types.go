package mapping

// InterfaceTypeMap maps SNMP ifType integer values to NetBox interface type strings
var InterfaceTypeMap = map[string]string{
	// Virtual Interfaces
	"24":  "virtual", // softwareLoopback
	"53":  "virtual", // propVirtual
	"112": "virtual", // virtualIpAddress
	"131": "virtual", // tunnel
	"135": "virtual", // l2vlan
	"136": "virtual", // l3ipvlan
	"137": "virtual", // l3ipxvlan
	"149": "virtual", // atmVirtual
	"150": "virtual", // mplsTunnel
	"202": "virtual", // virtualTg
	"222": "virtual", // ciscoISLvlan
	"246": "virtual", // ifPwType
	"258": "virtual", // vmwareVirtualNic
	"262": "virtual", // ifVfiType
	"272": "virtual", // vmwareNicTeam

	// Bridge and LAG Interfaces
	"209": "bridge", // bridge
	"161": "lag",    // ieee8023adLag

	// Wireless Interfaces
	"71":  "ieee802.11n",    // ieee80211
	"157": "other-wireless", // propWirelessP2P
	"180": "other-wireless", // propDocsWirelessMaclayer
	"181": "other-wireless", // propDocsWirelessUpstream
	"183": "other-wireless", // hiperlan2
	"184": "other-wireless", // propBWAp2Mp
	"188": "other-wireless", // radioMAC
	"189": "other-wireless", // atmRadio
	"237": "other-wireless", // ieee80216WMAN
	"252": "other-wireless", // capwapDot11Profile
	"253": "other-wireless", // capwapDot11Bss
	"254": "other-wireless", // capwapWtpVirtualRadio
	"259": "ieee802.15.4",   // ieee802154
	"281": "other-wireless", // xboxWireless

	// Cellular Interfaces
	"243": "4g", // wwanPP
	"244": "4g", // wwanPP2
	"300": "4g", // cpri

	// SONET/SDH Interfaces
	"39":  "sonet-oc3", // sonet
	"50":  "sonet-oc3", // sonetPath
	"51":  "sonet-oc3", // sonetVT
	"171": "sonet-oc3", // pos
	"185": "sonet-oc3", // sonetOverheadChannel

	// Fibre Channel Interfaces
	"56":  "1gfc-sfp", // fibreChannel
	"224": "1gfc-sfp", // fcipLink

	// InfiniBand Interfaces
	"199": "infiniband-sdr", // infiniband

	// Serial Interfaces
	"18":  "t1", // ds1
	"19":  "e1", // e1
	"30":  "t3", // ds3
	"22":  "t1", // propPointToPointSerial
	"33":  "t1", // rs232
	"64":  "t1", // v11
	"65":  "t1", // v36
	"66":  "t1", // g703at64k
	"67":  "t1", // g703at2mb
	"81":  "t1", // ds0
	"82":  "t1", // ds0Bundle
	"170": "t1", // ds1FDL

	// ATM/DSL Interfaces
	"37":  "xdsl", // atm
	"49":  "xdsl", // aal5
	"80":  "xdsl", // atmLogical
	"105": "xdsl", // atmDxi
	"106": "xdsl", // atmFuni
	"107": "xdsl", // atmIma
	"114": "xdsl", // ipOverAtm
	"134": "xdsl", // atmSubInterface
	"152": "xdsl", // voiceOverAtm
	"187": "xdsl", // aal2
	"197": "xdsl", // propAtm
	"234": "xdsl", // atmbond
	"94":  "xdsl", // adsl
	"95":  "xdsl", // radsl
	"96":  "xdsl", // sdsl
	"97":  "xdsl", // vdsl
	"143": "xdsl", // msdsl
	"154": "xdsl", // idsl
	"168": "xdsl", // hdsl2
	"169": "xdsl", // shdsl
	"191": "xdsl", // mvl
	"192": "xdsl", // reachDSL
	"230": "xdsl", // adsl2
	"238": "xdsl", // adsl2plus
	"251": "xdsl", // vdsl2
	"279": "xdsl", // gfast
	"282": "xdsl", // fastdsl

	// Coaxial Interfaces
	"127": "docsis", // docsCableMaclayer
	"128": "docsis", // docsCableDownstream
	"129": "docsis", // docsCableUpstream
	"205": "docsis", // docsCableUpstreamChannel
	"229": "docsis", // docsCableMCmtsDownstream
	"256": "docsis", // docsCableUpstreamRfPort
	"257": "docsis", // cableDownstreamRfPort
	"277": "docsis", // docsOfdmDownstream
	"278": "docsis", // docsOfdmaUpstream
	"283": "docsis", // docsCableScte55d1FwdOob
	"284": "docsis", // docsCableScte55d1RetOob
	"285": "docsis", // docsCableScte55d2DsOob
	"286": "docsis", // docsCableScte55d2UsOob
	"287": "docsis", // docsCableNdf
	"288": "docsis", // docsCableNdr

	// MoCA Interface
	"236": "moca", // mocaVersion1

	// PON Interfaces
	"207": "bpon", // pon155
	"208": "bpon", // pon622
	"250": "gpon", // gpon
	"266": "epon", // aluEpon
	"267": "epon", // aluEponOnu
	"268": "epon", // aluEponPhysicalUni
	"269": "epon", // aluEponLogicalLink
	"270": "gpon", // aluGponOnu
	"271": "gpon", // aluGponPhysicalUni

	// Stacking Interfaces
	"111": "cisco-stackwise", // stackToStack
}

func isEthernetInterfaceType(ifType string) bool {
	return ifType == "6" || // ethernetCsmacd
		ifType == "7" || // iso88023Csmacd
		ifType == "11" || // starLan
		ifType == "26" || // ethernet3Mbit
		ifType == "55" || // ieee80212
		ifType == "62" || // fastEther
		ifType == "69" || // fastEtherFX
		ifType == "117" || // gigabitEthernet
		ifType == "233" // aviciOpticalEther
}

func getEthernetInterfaceType(speed *int64) string {
	if *speed <= 100000 {
		return "100base-tx"
	}
	if *speed <= 1000000 {
		return "1000base-t"
	}
	if *speed <= 10000000 {
		return "10gbase-t"
	}
	if *speed <= 25000000 {
		return "25gbase-t"
	}
	return "100gbase-x"
}

// GetNetboxType maps an SNMP ifType integer to a NetBox interface type
func GetNetboxType(ifType, defaultInterfaceType string, speed *int64) string {
	if isEthernetInterfaceType(ifType) {
		if speed != nil && *speed > 0 {
			return getEthernetInterfaceType(speed)
		}
		return "other"
	}
	if netboxType, found := InterfaceTypeMap[ifType]; found {
		return netboxType
	}
	if defaultInterfaceType != "" {
		return defaultInterfaceType
	}
	return "other"
}
