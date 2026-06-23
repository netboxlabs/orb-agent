package qbridge

import (
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
