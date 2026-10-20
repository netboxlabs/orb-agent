package octets

import (
	"bytes"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func TestText(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"empty", "", ""},
		{"text is kept", "GigabitEthernet1/0/1", "GigabitEthernet1/0/1"},
		{"surrounding space is trimmed", "  eth0 \r\n", "eth0"},
		{"only space is empty", "   ", ""},
		{"UTF-8 text is kept", "Café — uplink", "Café — uplink"},
		{"a tab inside text is kept", "core\tuplink", "core\tuplink"},
		{"NUL padding after text is trimmed", "eth0\x00\x00", "eth0"},
		// Dell Networking OS answers an unset ifAlias with two NULs.
		{"only NUL is empty", "\x00\x00", ""},
		{"an all-zero MAC is empty", "\x00\x00\x00\x00\x00\x00", ""},
		// The Arista EOS recording: ifPhysAddress, LLDP and ARP values are binary.
		{"binary MAC is hex", "\x00\x1b!\xbb\xe6\xf0", "00:1b:21:bb:e6:f0"},
		{"binary chassis ID is hex", "\xc4}O\xd4I\x1d", "c4:7d:4f:d4:49:1d"},
		{"a MAC of printable Latin-1 bytes is hex", "\xc4}O\xc4F\xff", "c4:7d:4f:c4:46:ff"},
		{"another MAC of printable Latin-1 bytes is hex", "\xc4}O\xc4F\xc0", "c4:7d:4f:c4:46:c0"},
		{"binary that happens to be valid UTF-8 is hex", "\x00\x1b! 0@", "00:1b:21:20:30:40"},
		{"binary ending in NUL keeps every byte", "\xa4\xbbm\xe5A\x00", "a4:bb:6d:e5:41:00"},
		{"binary ending in a space keeps every byte", "\xa4\xbbm\xe5A ", "a4:bb:6d:e5:41:20"},
		{"binary ending in NBSP keeps every byte", "\xa4\xbbm\xe5A\xa0", "a4:bb:6d:e5:41:a0"},
		{"a NUL inside text is binary", "a\x00b", "61:00:62"},
		{"a C1 control is binary", "\u0085x", "c2:85:78"},
		{"DEL is binary", "a\x7f", "61:7f"},
		{"text that is not UTF-8 is hex", "Caf\xe9", "43:61:66:e9"},
		{"text cut inside a character is hex", "up\xe2\x80", "75:70:e2:80"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Text([]byte(tt.raw)))
		})
	}
}

// Two binary values that differ only in bytes that are not UTF-8, or only in
// a last byte that trimming would remove, stay two values. Replacing those
// bytes with U+FFFD, or trimming before deciding, would give them one label.
func TestText_DistinctBinaryStaysDistinct(t *testing.T) {
	seen := map[string]string{}
	for _, raw := range []string{
		"\x00\x1b!\xbb\xe6\xf0", "\x00\x1b!\xbb\xe6\xea",
		"\xa4\xbbm\xe5A\x00", "\xa4\xbbm\xe5A ", "\xa4\xbbm\xe5A\xa0",
	} {
		got := Text([]byte(raw))
		if other, ok := seen[got]; ok {
			t.Fatalf("%q and %q both render %q", other, raw, got)
		}
		seen[got] = raw
	}
}

func TestHex(t *testing.T) {
	assert.Equal(t, "", Hex(nil))
	assert.Equal(t, "00:1b:21:bb:e6:f0", Hex([]byte("\x00\x1b!\xbb\xe6\xf0")))
}

func FuzzText(f *testing.F) {
	for _, seed := range []string{"", "eth0", "Caf\xe9", "\x00\x1b!\xbb\xe6\xf0", "\xff\xfe", "a\x00b", "\x00\x00"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		got := Text(raw)
		if !utf8.ValidString(got) {
			t.Fatalf("Text(%q) = %q is not valid UTF-8", raw, got)
		}
		// A value is either text, or every byte of it in hex.
		if got != "" && got != Hex(raw) && !bytes.Contains(raw, []byte(got)) {
			t.Fatalf("Text(%q) = %q is neither the text nor the hex of it", raw, got)
		}
	})
}

// Hex is one-to-one: two different values never render alike.
func FuzzHex(f *testing.F) {
	f.Add([]byte("\x00\x1b!\xbb\xe6\xf0"), []byte("\x00\x1b!\xbb\xe6\xea"))
	f.Fuzz(func(t *testing.T, a, b []byte) {
		if !bytes.Equal(a, b) && Hex(a) == Hex(b) {
			t.Fatalf("Hex(%q) == Hex(%q) == %q", a, b, Hex(a))
		}
	})
}
