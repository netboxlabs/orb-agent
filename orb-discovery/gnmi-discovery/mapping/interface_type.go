package mapping

import (
	"regexp"
	"strings"
)

// ocSpeedToKbps maps an OpenConfig openconfig-if-ethernet port-speed identityref
// (module prefix already stripped by identityRefBase) to a NetBox interface speed
// in kbps. SPEED_UNKNOWN is intentionally absent so it never sets a speed.
var ocSpeedToKbps = map[string]int64{
	"SPEED_10MB":   10000,
	"SPEED_100MB":  100000,
	"SPEED_1GB":    1000000,
	"SPEED_2500MB": 2500000,
	"SPEED_5GB":    5000000,
	"SPEED_10GB":   10000000,
	"SPEED_25GB":   25000000,
	"SPEED_40GB":   40000000,
	"SPEED_50GB":   50000000,
	"SPEED_100GB":  100000000,
	"SPEED_200GB":  200000000,
	"SPEED_400GB":  400000000,
	"SPEED_800GB":  800000000,
}

// ocSpeedToType maps a port-speed identityref base to a representative NetBox
// media interface type. Mirrors device-discovery's detect_type_by_speed table.
// SPEED_10MB and SPEED_800GB have no clean NetBox media slug used by the reference
// implementations, so they set Speed (via ocSpeedToKbps) but not a speed-inferred
// type — they fall through to the policy default.
var ocSpeedToType = map[string]string{
	"SPEED_100MB":  "100base-tx",
	"SPEED_1GB":    "1000base-t",
	"SPEED_2500MB": "2.5gbase-t",
	"SPEED_5GB":    "5gbase-t",
	"SPEED_10GB":   "10gbase-x-sfpp",
	"SPEED_25GB":   "25gbase-x-sfp28",
	"SPEED_40GB":   "40gbase-x-qsfpp",
	"SPEED_50GB":   "50gbase-x-sfp56",
	"SPEED_100GB":  "100gbase-x-qsfp28",
	"SPEED_200GB":  "200gbase-x-qsfp56",
	"SPEED_400GB":  "400gbase-x-qsfp112",
}

// ocDuplex maps an OpenConfig negotiated-duplex-mode (identityRefBase-normalized:
// upper, prefix-stripped) to a NetBox interface duplex. Only the operational
// FULL/HALF are mapped; AUTO/absent leave Duplex unset.
var ocDuplex = map[string]string{
	"FULL": "full",
	"HALF": "half",
}

// compiledIfacePattern is a name regex paired with the NetBox type it implies.
type compiledIfacePattern struct {
	re  *regexp.Regexp
	typ string
}

// defaultInterfacePatterns is a built-in cross-vendor name->type table modeled on
// device-discovery's DEFAULT_INTERFACE_PATTERNS (most specific first). Compiled
// once at init. Cisco/Juniper names encode physical media reliably, so these are
// matched before the speed-based tier. The Nokia "ethernet-N/N" name is OMITTED
// (speed-agnostic; gNMI's authoritative port-speed resolves Nokia rates instead).
// The 2-letter abbreviations are anchored with \d so they don't over-match
// unrelated names; the unambiguous long forms stay prefix-only.
//
// Juniper "et-" is also OMITTED: the et- prefix spans 40G AND 100G, so a fixed
// name rule would mis-type half of them. device-discovery keeps et-→40G because
// NAPALM often lacks speed, but gNMI reports an authoritative port-speed, so we
// let the speed tier resolve et- rates. The unambiguous xe-/ge- are retained.
var defaultInterfacePatterns = []compiledIfacePattern{
	{regexp.MustCompile(`^(HundredGig|Hu\d)`), "100gbase-x-qsfp28"},
	{regexp.MustCompile(`^(FortyGig|Fo\d)`), "40gbase-x-qsfpp"},
	{regexp.MustCompile(`^(TwentyFiveGig|Twe\d)`), "25gbase-x-sfp28"},
	{regexp.MustCompile(`^(TenGig|Te\d)`), "10gbase-x-sfpp"},
	{regexp.MustCompile(`^(FiveGig|Fi\d)`), "5gbase-t"},
	{regexp.MustCompile(`^(TwoGig|Tw\d)`), "2.5gbase-t"},
	{regexp.MustCompile(`^(GigabitEthernet|Gi)\d+`), "1000base-t"},
	{regexp.MustCompile(`^(FastEthernet|Fa)\d+`), "100base-tx"},
	{regexp.MustCompile(`^xe-\d+/\d+/\d+`), "10gbase-x-sfpp"},
	{regexp.MustCompile(`^ge-\d+/\d+/\d+`), "1000base-t"},
	{regexp.MustCompile(`^([Pp]ort-[Cc]hannel|Po)\d+`), "lag"},
	{regexp.MustCompile(`^ae\d+`), "lag"},
	{regexp.MustCompile(`^Bundle-Ether\d+`), "lag"},
	// Huawei VRP/CloudEngine media names (10GE/25GE/40GE/100GE, descending so the
	// longer prefixes win; bare GE is Huawei 1G) plus Eth-Trunk (LAG) and Vlanif
	// (SVI). These tokens are vendor-unique and do not collide with the rules
	// above, so they benefit fallback-to-_base discovery too. PortChannel (no
	// hyphen) covers SONiC/Dell — the `Po\d+` rule above requires a digit right
	// after "Po" so it does not match "PortChannelNN".
	{regexp.MustCompile(`^100GE\d`), "100gbase-x-qsfp28"},
	{regexp.MustCompile(`^40GE\d`), "40gbase-x-qsfpp"},
	{regexp.MustCompile(`^25GE\d`), "25gbase-x-sfp28"},
	{regexp.MustCompile(`^10GE\d`), "10gbase-x-sfpp"},
	{regexp.MustCompile(`^GE\d`), "1000base-t"},
	{regexp.MustCompile(`^Eth-Trunk\d+`), "lag"},
	{regexp.MustCompile(`^Vlanif\d+`), "virtual"},
	{regexp.MustCompile(`^PortChannel\d+`), "lag"},
}

// normalizeMAC upper-cases a MAC and rejects the all-zero address. Returns ""
// when the input is empty or all-zero (so no MACAddress is emitted).
func normalizeMAC(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" || s == "00:00:00:00:00:00" {
		return ""
	}
	return s
}

// resolveInterfaceType resolves a NetBox interface type by precedence:
//  1. user interface_patterns (first match) — operator override
//  2. OpenConfig state/type map (lag/virtual/tunnel classes)
//  3. built-in name patterns (media-encoding vendor names)
//  4. speed-based media inference
//  5. defaultType ("other" or the policy interface default)
//
// ocTypeBase and speedEnum are the identityRefBase-stripped values of the
// state/type and ethernet/state/port-speed leaves ("" when absent). userPatterns
// is the per-call compiled policy interface_patterns.
func resolveInterfaceType(name, ocTypeBase, speedEnum, defaultType string, userPatterns []compiledIfacePattern) string {
	for _, p := range userPatterns {
		// Defensive: skip an empty pattern type so it can never set Interface.Type
		// to "" (policy validation already rejects these) and never short-circuit
		// the fallback chain on an empty result.
		if p.typ != "" && p.re.MatchString(name) {
			return p.typ
		}
	}
	if t, ok := ocInterfaceTypeToNetBox[ocTypeBase]; ok {
		return t
	}
	for _, p := range defaultInterfacePatterns {
		if p.re.MatchString(name) {
			return p.typ
		}
	}
	if t, ok := ocSpeedToType[speedEnum]; ok {
		return t
	}
	return defaultType
}
