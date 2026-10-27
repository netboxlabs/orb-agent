package qbridge

import (
	"reflect"
	"testing"
)

// ciscoTestBitmap encodes VLAN IDs using Cisco's MSB-first bitmap layout.
// It is test-only and independent of the production decoder.
func ciscoTestBitmap(offset int, vids ...int) []byte {
	var bitmap []byte
	for _, vid := range vids {
		position := vid - offset
		if position < 0 || position >= 2048 {
			panic("VLAN outside bitmap range")
		}
		byteIndex := position / 8
		for len(bitmap) <= byteIndex {
			bitmap = append(bitmap, 0)
		}
		bitmap[byteIndex] |= byte(0x80 >> uint(position%8))
	}
	return bitmap
}

func TestDecodeCiscoActiveVlans(t *testing.T) {
	tests := []struct {
		name      string
		first     []byte
		second    []byte
		hasFirst  bool
		hasSecond bool
		want      []int
		wantOK    bool
	}{
		{
			name:  "Nexus Ethernet1/48 active VLANs",
			first: ciscoTestBitmap(0, 610, 702),
			second: ciscoTestBitmap(2048,
				3440, 3458, 3461, 3504, 3533, 3560, 3640,
				3747, 3752, 3854, 3871, 3879, 3901),
			hasFirst:  true,
			hasSecond: true,
			want: []int{
				610, 702, 3440, 3458, 3461, 3504, 3533,
				3560, 3640, 3747, 3752, 3854, 3871, 3879, 3901,
			},
			wantOK: true,
		},
		{
			name:      "bitmap boundaries",
			first:     ciscoTestBitmap(0, 1, 7, 8, 2047),
			second:    ciscoTestBitmap(2048, 2048, 2055, 2056, 4094),
			hasFirst:  true,
			hasSecond: true,
			want:      []int{1, 7, 8, 2047, 2048, 2055, 2056, 4094},
			wantOK:    true,
		},
		{
			name:      "reserved VLAN IDs excluded",
			first:     ciscoTestBitmap(0, 0, 1),
			second:    ciscoTestBitmap(2048, 4094, 4095),
			hasFirst:  true,
			hasSecond: true,
			want:      []int{1, 4094},
			wantOK:    true,
		},
		{
			name:      "present empty bitmaps",
			first:     []byte{},
			second:    []byte{},
			hasFirst:  true,
			hasSecond: true,
			want:      []int{},
			wantOK:    true,
		},
		{
			name:      "missing first row",
			second:    ciscoTestBitmap(2048, 3752),
			hasSecond: true,
			wantOK:    false,
		},
		{
			name:     "missing second row",
			first:    ciscoTestBitmap(0, 610),
			hasFirst: true,
			wantOK:   false,
		},
		{
			name:      "oversized first bitmap",
			first:     make([]byte, 257),
			second:    []byte{},
			hasFirst:  true,
			hasSecond: true,
			wantOK:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := DecodeCiscoActiveVlans(
				tt.first, tt.second, tt.hasFirst, tt.hasSecond,
			)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("VLANs = %v, want %v", got, tt.want)
			}
		})
	}
}
