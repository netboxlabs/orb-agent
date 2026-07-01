package backend

import "testing"

func TestConfigValueOrDefault_String(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		config   map[string]any
		key      string
		fallback string
		want     string
	}{
		{"string present", map[string]any{"host": "myhost"}, "host", "localhost", "myhost"},
		{"key absent", map[string]any{}, "host", "localhost", "localhost"},
		// Present-but-not-string values coerce via %v when a string is requested
		// (this is what lets a YAML-numeric "port" read as a string).
		{"int present coerces", map[string]any{"port": 8073}, "port", "8080", "8073"},
		{"null present coerces to <nil>", map[string]any{"host": nil}, "host", "localhost", "<nil>"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ConfigValueOrDefault(tc.config, tc.key, tc.fallback); got != tc.want {
				t.Errorf("ConfigValueOrDefault(%v, %q, %q) = %q; want %q",
					tc.config, tc.key, tc.fallback, got, tc.want)
			}
		})
	}
}

func TestConfigValueOrDefault_Bool(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		config   map[string]any
		key      string
		fallback bool
		want     bool
	}{
		{"bool true present", map[string]any{"dry_run": true}, "dry_run", false, true},
		{"bool false present", map[string]any{"dry_run": false}, "dry_run", true, false},
		{"key absent", map[string]any{}, "dry_run", false, false},
		// A non-bool present value is NOT coerced for a bool read: strict, fallback.
		{"wrong type falls back", map[string]any{"dry_run": "true"}, "dry_run", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ConfigValueOrDefault(tc.config, tc.key, tc.fallback); got != tc.want {
				t.Errorf("ConfigValueOrDefault(%v, %q, %v) = %v; want %v",
					tc.config, tc.key, tc.fallback, got, tc.want)
			}
		})
	}
}

// TestConfigValueOrDefault_PortIntOrString locks the behavior David asked about:
// a single generic helper reads "port" whether YAML decoded it as an int
// (unquoted) or a string (quoted), always yielding a string.
func TestConfigValueOrDefault_PortIntOrString(t *testing.T) {
	t.Parallel()
	if got := ConfigValueOrDefault(map[string]any{"port": 8073}, "port", "8080"); got != "8073" {
		t.Errorf("int port = %q; want %q", got, "8073")
	}
	if got := ConfigValueOrDefault(map[string]any{"port": "9090"}, "port", "8080"); got != "9090" {
		t.Errorf("string port = %q; want %q", got, "9090")
	}
	if got := ConfigValueOrDefault(map[string]any{}, "port", "8080"); got != "8080" {
		t.Errorf("absent port = %q; want %q", got, "8080")
	}
}
