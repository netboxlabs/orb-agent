package qbridge

import (
	"errors"
	"strconv"
	"strings"
)

// ErrMissingTranslation is returned by DecodePortMask when the
// dot1dBasePortIfIndex table is empty/nil. Callers must treat this as
// "Interface mutation skipped for this host" — there is no safe fallback.
var ErrMissingTranslation = errors.New("qbridge: dot1dBasePortIfIndex translation table missing")

// DecodePortMask expands a Q-BRIDGE OCTET STRING port mask into a sorted
// list of ifIndex values.
//
// Bit i (0-indexed, MSB-first within each byte) corresponds to bridge
// port (i+1). The bridge-port→ifIndex translation is supplied by the
// caller and comes from BRIDGE-MIB dot1dBasePortIfIndex.
//
// Behavior:
//   - empty mask + non-empty translation table → [], nil
//   - empty/nil translation table → nil, ErrMissingTranslation
//     (callers must NOT fall back to identity mapping; that would silently
//     mutate wrong interfaces on switches that allocate bridge ports
//     separately from ifIndex.)
//   - bitmap names a bridge port not in the translation table → silently
//     skipped with no log here (caller logs at debug); see spec rev. 3
//     "Bitmap decoding / Partial-table case".
//
// The returned slice is in bridge-port order (== bit order); callers
// that need numerical-ifIndex order should sort.
func DecodePortMask(octets []byte, basePortToIfIndex map[int]int) ([]int, error) {
	if len(basePortToIfIndex) == 0 {
		return nil, ErrMissingTranslation
	}
	out := make([]int, 0)
	for byteIdx, b := range octets {
		for bit := 0; bit < 8; bit++ {
			if b&(1<<(7-bit)) == 0 {
				continue
			}
			bridgePort := byteIdx*8 + bit + 1
			ifIndex, ok := basePortToIfIndex[bridgePort]
			if !ok {
				// Silently skip; not fatal. Spec rev. 3 §"Bitmap decoding / Partial-table case".
				continue
			}
			out = append(out, ifIndex)
		}
	}
	return out, nil
}

// maxBridgePort is the highest bridge port number BRIDGE-MIB defines
// (dot1dBasePort is an INTEGER in 1..65535). A text list naming a larger
// number is not a port list, and nothing is ever sized from such a number.
const maxBridgePort = 65535

// asciiPortList reads a value as the text form of a port list: the bridge
// port numbers, comma separated, as some platforms publish
// dot1qVlanStaticEgressPorts and dot1qVlanStaticUntaggedPorts by default in
// place of the bitmap the MIB defines. A zero entry names no port, and a
// number past maxBridgePort makes the value not a list. Whether a host's
// values are that text at all is decided by listsAreText; this only says
// whether one value parses as it.
func asciiPortList(v []byte) ([]int, bool) {
	if len(v) == 0 {
		return nil, false
	}
	for _, b := range v {
		if b != ',' && (b < '0' || b > '9') {
			return nil, false
		}
	}
	var ports []int
	for _, field := range strings.Split(string(v), ",") {
		if field == "" {
			return nil, false
		}
		n, err := strconv.Atoi(field)
		if err != nil || n > maxBridgePort {
			return nil, false
		}
		if n > 0 {
			ports = append(ports, n)
		}
	}
	return ports, true
}

// listsAreText decides, once per host, whether its Q-BRIDGE port lists are the
// text form. A bitmap may be made of digit and comma bytes, so parsing alone
// cannot tell the two apart: the three bytes of "0,1" are a legal bitmap of
// ports 3, 4, 11, 13, 14, 19, 20 and 24. The lists are text only when every
// non-empty value parses as a list and reading them as bitmaps is impossible:
// some list names a port beyond what a bitmap of its length can hold, or some
// value read as a bitmap names a port the translation table does not have
// while no list does. A host whose values read both ways keeps the bitmap the
// MIB defines. A list naming a port the table lacks is not held against the
// text reading on its own: devices list bridge ports they never map, as
// bitmaps set bits for them, and both readers skip such a port.
func listsAreText(egress, untagged map[int][]byte, basePortToIfIndex map[int]int) bool {
	sawList, beyondBitmap, bitmapUnknown, listUnknown := false, false, false, false
	for _, table := range []map[int][]byte{egress, untagged} {
		for _, v := range table {
			if len(v) == 0 {
				continue
			}
			ports, ok := asciiPortList(v)
			if !ok {
				return false
			}
			sawList = true
			for _, p := range ports {
				if p > 8*len(v) {
					beyondBitmap = true
				}
				if _, known := basePortToIfIndex[p]; !known {
					listUnknown = true
				}
			}
			if bitmapNamesUnknownPort(v, basePortToIfIndex) {
				bitmapUnknown = true
			}
		}
	}
	return sawList && (beyondBitmap || (bitmapUnknown && !listUnknown))
}

// bitmapNamesUnknownPort reports whether v, read as a bitmap, sets a bit for a
// bridge port the translation table does not know.
func bitmapNamesUnknownPort(v []byte, basePortToIfIndex map[int]int) bool {
	for byteIdx, b := range v {
		for bit := 0; bit < 8; bit++ {
			if b&(1<<(7-bit)) == 0 {
				continue
			}
			if _, known := basePortToIfIndex[byteIdx*8+bit+1]; !known {
				return true
			}
		}
	}
	return false
}

// listsToBitmaps decodes a host's text port lists, each once, into the bitmaps
// the MIB defines, so membership is then read bit by bit as on any other host
// rather than by parsing the list again for every interface and VLAN pair. A
// value that does not parse is kept as it is.
func listsToBitmaps(table map[int][]byte) map[int][]byte {
	out := make(map[int][]byte, len(table))
	for vid, v := range table {
		ports, ok := asciiPortList(v)
		if !ok {
			if len(v) == 0 {
				out[vid] = []byte{}
				continue
			}
			out[vid] = v
			continue
		}
		maxPort := 0
		for _, p := range ports {
			if p > maxPort {
				maxPort = p
			}
		}
		mask := make([]byte, (maxPort+7)/8)
		for _, p := range ports {
			mask[(p-1)/8] |= 1 << (7 - (p-1)%8)
		}
		out[vid] = mask
	}
	return out
}
