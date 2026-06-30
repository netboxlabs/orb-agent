package backend

import "testing"

func TestConfigStringOrDefault(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		config   map[string]any
		key      string
		fallback string
		want     string
	}{
		{
			name:     "string present",
			config:   map[string]any{"host": "myhost"},
			key:      "host",
			fallback: "localhost",
			want:     "myhost",
		},
		{
			name:     "key absent",
			config:   map[string]any{},
			key:      "host",
			fallback: "localhost",
			want:     "localhost",
		},
		{
			name:     "null value",
			config:   map[string]any{"host": nil},
			key:      "host",
			fallback: "localhost",
			want:     "localhost",
		},
		{
			name:     "wrong type (int)",
			config:   map[string]any{"host": 42},
			key:      "host",
			fallback: "localhost",
			want:     "localhost",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ConfigStringOrDefault(tc.config, tc.key, tc.fallback)
			if got != tc.want {
				t.Errorf("ConfigStringOrDefault(%v, %q, %q) = %q; want %q",
					tc.config, tc.key, tc.fallback, got, tc.want)
			}
		})
	}
}

func TestConfigValueOrDefault(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		config   map[string]any
		key      string
		fallback string
		want     string
	}{
		{
			name:     "int present (YAML-parsed port)",
			config:   map[string]any{"port": 8073},
			key:      "port",
			fallback: "8080",
			want:     "8073",
		},
		{
			name:     "string present",
			config:   map[string]any{"port": "9090"},
			key:      "port",
			fallback: "8080",
			want:     "9090",
		},
		{
			name:     "key absent",
			config:   map[string]any{},
			key:      "port",
			fallback: "8080",
			want:     "8080",
		},
		{
			name:     "null value present stringifies (matches the old fmt.Sprintf reads)",
			config:   map[string]any{"port": nil},
			key:      "port",
			fallback: "8080",
			want:     "<nil>",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ConfigValueOrDefault(tc.config, tc.key, tc.fallback)
			if got != tc.want {
				t.Errorf("ConfigValueOrDefault(%v, %q, %q) = %q; want %q",
					tc.config, tc.key, tc.fallback, got, tc.want)
			}
		})
	}
}

func TestConfigBoolOrDefault(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		config   map[string]any
		key      string
		fallback bool
		want     bool
	}{
		{
			name:     "bool true present",
			config:   map[string]any{"dry_run": true},
			key:      "dry_run",
			fallback: false,
			want:     true,
		},
		{
			name:     "bool false present",
			config:   map[string]any{"dry_run": false},
			key:      "dry_run",
			fallback: true,
			want:     false,
		},
		{
			name:     "key absent",
			config:   map[string]any{},
			key:      "dry_run",
			fallback: false,
			want:     false,
		},
		{
			name:     "wrong type (string)",
			config:   map[string]any{"dry_run": "true"},
			key:      "dry_run",
			fallback: false,
			want:     false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ConfigBoolOrDefault(tc.config, tc.key, tc.fallback)
			if got != tc.want {
				t.Errorf("ConfigBoolOrDefault(%v, %q, %v) = %v; want %v",
					tc.config, tc.key, tc.fallback, got, tc.want)
			}
		})
	}
}
