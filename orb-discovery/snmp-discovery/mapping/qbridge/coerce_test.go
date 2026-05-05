package qbridge

import "testing"

func TestCoerceVid(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want *int
	}{
		{"valid int", 100, intPtr(100)},
		{"valid string", "200", intPtr(200)},
		{"vid 1 boundary", 1, intPtr(1)},
		{"vid 4094 boundary", 4094, intPtr(4094)},
		{"vid 0 rejected", 0, nil},
		{"vid 4095 rejected", 4095, nil},
		{"vid 4096 rejected", 4096, nil},
		{"negative rejected", -1, nil},
		{"non-numeric string rejected", "abc", nil},
		{"nil rejected", nil, nil},
		{"bool true rejected", true, nil},
		{"bool false rejected", false, nil},
		{"int64 valid", int64(500), intPtr(500)},
		{"uint valid", uint(750), intPtr(750)},
		{"empty string rejected", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CoerceVid(tt.in)
			if (got == nil) != (tt.want == nil) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			if got != nil && *got != *tt.want {
				t.Fatalf("got *%d, want *%d", *got, *tt.want)
			}
		})
	}
}
