package qbridge

import "testing"

func TestMode_String(t *testing.T) {
	cases := map[Mode]string{
		ModeUnknown:  "unknown",
		ModeAccess:   "access",
		ModeTrunk:    "trunk",
		ModeTrunkAll: "trunk-all",
		ModeRouted:   "routed",
	}
	for m, want := range cases {
		if got := m.String(); got != want {
			t.Errorf("Mode(%d).String(): got %q, want %q", m, got, want)
		}
	}
}

func TestIntPtr(t *testing.T) {
	p := intPtr(42)
	if p == nil || *p != 42 {
		t.Errorf("intPtr(42): got %v, want pointer to 42", p)
	}
}
