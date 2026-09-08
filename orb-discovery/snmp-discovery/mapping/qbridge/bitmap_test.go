package qbridge

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestDecodePortMask(t *testing.T) {
	bp := map[int]int{
		1: 101, 2: 102, 3: 103, 4: 104,
		5: 105, 6: 106, 7: 107, 8: 108,
		9: 109, 10: 110,
	}
	tests := []struct {
		name    string
		octets  []byte
		bp      map[int]int
		want    []int
		wantErr error
	}{
		{
			name:   "empty mask returns empty",
			octets: []byte{0x00},
			bp:     bp,
			want:   []int{},
		},
		{
			name:   "first bit -> port 1 -> ifIndex 101",
			octets: []byte{0x80},
			bp:     bp,
			want:   []int{101},
		},
		{
			name:   "single byte all bits set -> ports 1..8",
			octets: []byte{0xFF},
			bp:     bp,
			want:   []int{101, 102, 103, 104, 105, 106, 107, 108},
		},
		{
			name:   "multi-byte sparse",
			octets: []byte{0x01, 0x80}, // port 8 + port 9
			bp:     bp,
			want:   []int{108, 109},
		},
		{
			name:   "unmapped bridge port silently skipped",
			octets: []byte{0xC0}, // port 1 + port 2; map only has port 1
			bp:     map[int]int{1: 101},
			want:   []int{101},
		},
		{
			name:    "missing translation table errors",
			octets:  []byte{0xFF},
			bp:      map[int]int{},
			wantErr: ErrMissingTranslation,
		},
		{
			name:    "nil translation table errors",
			octets:  []byte{0xFF},
			bp:      nil,
			wantErr: ErrMissingTranslation,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodePortMask(tt.octets, tt.bp)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err: got %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// Some platforms publish a Q-BRIDGE port list as the ASCII text of the bridge
// port numbers, comma separated, rather than as a bitmap. The host's lists are
// read as text only when reading them as bitmaps is impossible: a listed port
// beyond what a bitmap of that length could hold, or a bitmap reading that
// names a bridge port the translation table does not know. A value that reads
// both ways stays the bitmap the MIB defines.
func TestListsAreText(t *testing.T) {
	junosPorts := map[int]int{4097: 513, 4098: 520, 4099: 518}
	smallPorts := map[int]int{}
	for bp := 1; bp <= 24; bp++ {
		smallPorts[bp] = 100 + bp
	}
	cases := []struct {
		name      string
		egress    map[int][]byte
		untagged  map[int][]byte
		basePorts map[int]int
		want      bool
	}{
		{
			name:      "a list naming a port no bitmap this long could hold",
			egress:    map[int][]byte{23: []byte("0,4097,4099"), 4004: []byte("0,4097,4099,4098")},
			untagged:  map[int][]byte{23: []byte(""), 4004: []byte("4098")},
			basePorts: junosPorts,
			want:      true,
		},
		{
			name:      "a value that reads as a legal bitmap of known ports stays a bitmap",
			egress:    map[int][]byte{10: {0x30, 0x2c, 0x31}},
			untagged:  map[int][]byte{},
			basePorts: smallPorts,
			want:      false,
		},
		{
			name:      "a short list whose bitmap reading names an unknown port is text",
			egress:    map[int][]byte{10: []byte("0,1,2")},
			untagged:  map[int][]byte{},
			basePorts: map[int]int{1: 101, 2: 102},
			want:      true,
		},
		{
			name:      "one binary mask beside the lists means the host uses bitmaps",
			egress:    map[int][]byte{23: []byte("0,4097"), 24: {0xff, 0x00}},
			untagged:  map[int][]byte{},
			basePorts: junosPorts,
			want:      false,
		},
		{
			name:      "a list naming a port the table lacks is still text when a port lies beyond any bitmap",
			egress:    map[int][]byte{23: []byte("0,4097,4106")},
			untagged:  map[int][]byte{},
			basePorts: junosPorts,
			want:      true,
		},
		{
			name:      "a short list naming an unknown port, with the bitmap reading also naming one, stays a bitmap",
			egress:    map[int][]byte{10: []byte("0,1,9")},
			untagged:  map[int][]byte{},
			basePorts: map[int]int{1: 101, 2: 102},
			want:      false,
		},
		{
			name:      "empty tables decide nothing",
			egress:    map[int][]byte{1: {}},
			untagged:  map[int][]byte{},
			basePorts: junosPorts,
			want:      false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := listsAreText(tc.egress, tc.untagged, tc.basePorts); got != tc.want {
				t.Errorf("listsAreText: got %v, want %v", got, tc.want)
			}
		})
	}
}

// A host's text lists are decoded once, each into the bitmap the MIB defines,
// so membership is then read bit by bit as on any other host; a zero entry
// sets no bit and an empty list is an empty bitmap.
func TestListsToBitmaps(t *testing.T) {
	got := listsToBitmaps(map[int][]byte{
		23:   []byte("0,4097,4099"),
		4004: []byte("0,4097,4099,4098"),
		1:    []byte(""),
	})
	want := map[int][]byte{
		23:   maskWithPorts(4097, 4099),
		4004: maskWithPorts(4097, 4098, 4099),
		1:    {},
	}
	for vid, mask := range want {
		if !bytes.Equal(got[vid], mask) {
			t.Errorf("vid %d: got %x, want %x", vid, got[vid], mask)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d rows, want %d", len(got), len(want))
	}
}
