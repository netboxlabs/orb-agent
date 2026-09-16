package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeLogValue(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"unchanged", "/etc/snmp/profiles", "/etc/snmp/profiles"},
		{"line feed", "dir\nlevel=ERROR msg=forged", "dir level=ERROR msg=forged"},
		{"carriage return", "dir\rlevel=ERROR msg=forged", "dir level=ERROR msg=forged"},
		{"carriage return line feed", "dir\r\nlevel=ERROR msg=forged", "dir level=ERROR msg=forged"},
		{"repeated", "a\nb\r\nc\rd", "a b c d"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, SanitizeLogValue(tt.value))
		})
	}
}
