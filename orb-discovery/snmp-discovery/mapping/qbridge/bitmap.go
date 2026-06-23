package qbridge

import "errors"

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
