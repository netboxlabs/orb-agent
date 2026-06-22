package qbridge

import "strconv"

// CoerceVid converts an arbitrary value into a *int VLAN ID in [1, 4094].
//
// Mirrors device-discovery/custom_napalm/_vlan.py::coerce_vid. Bool is
// rejected explicitly because Go's reflect would otherwise treat it as
// untyped 0/1 in some paths; vendor extractors that mistakenly hand
// CoerceVid a bool should not silently emit VLAN 1.
//
// Returns nil for: out-of-range values (including the sentinels 0/4095/4096),
// non-numeric strings, nil, bool, and any other unsupported type.
func CoerceVid(value any) *int {
	if value == nil {
		return nil
	}
	var v int
	switch x := value.(type) {
	case bool:
		return nil
	case int:
		v = x
	case int8:
		v = int(x)
	case int16:
		v = int(x)
	case int32:
		v = int(x)
	case int64:
		v = int(x)
	case uint:
		if x > 4094 {
			return nil
		}
		v = int(x)
	case uint8:
		v = int(x)
	case uint16:
		v = int(x)
	case uint32:
		if x > 4094 {
			return nil
		}
		v = int(x)
	case uint64:
		if x > 4094 {
			return nil
		}
		v = int(x)
	case string:
		if x == "" {
			return nil
		}
		parsed, err := strconv.Atoi(x)
		if err != nil {
			return nil
		}
		v = parsed
	default:
		return nil
	}
	if v < 1 || v > 4094 {
		return nil
	}
	return intPtr(v)
}
