package targets

import (
	"testing"
)

func TestExpand(t *testing.T) {
	tests := []struct {
		name        string
		target      string
		want        []string
		shouldError bool
	}{
		{
			name:   "Single IP",
			target: "192.168.1.1",
			want:   []string{"192.168.1.1"},
		},
		{
			name:   "Hostname",
			target: "example.com",
			want:   []string{"example.com"},
		},
		{
			name:   "Hostname With Hyphen",
			target: "my-hostname",
			want:   []string{"my-hostname"},
		},
		{
			name:   "Hostname Starting With IP And Hyphen",
			target: "10.10.10.1-host",
			want:   []string{"10.10.10.1-host"},
		},
		{
			name:        "Invalid CIDR",
			target:      "192.168.1.1/33",
			shouldError: true,
		},
		{
			name:        "Invalid IP Range",
			target:      "192.168.1.1-300",
			shouldError: true,
		},
		{
			name:        "Invalid IP Range Format",
			target:      "192.168.1.1-2-3",
			shouldError: true,
		},
		{
			name:        "Invalid Base IP",
			target:      "256.0.0.1-5",
			shouldError: true,
		},
		{
			name:        "Range End Less Than Start",
			target:      "192.168.1.100-50",
			shouldError: true,
		},
		{
			name:        "IPv6 CIDR",
			target:      "2001:db8::/32",
			shouldError: true,
		},
		{
			name:        "IPv6 Range",
			target:      "2001:db8::1-100",
			shouldError: true,
		},
		{
			name:   "Full IP Range",
			target: "10.10.10.0-10.10.10.2",
			want:   []string{"10.10.10.0", "10.10.10.1", "10.10.10.2"},
		},
		{
			name:   "Full IP Range With CIDR Suffix",
			target: "10.10.10.0/24-10.10.10.2/24",
			want:   []string{"10.10.10.0", "10.10.10.1", "10.10.10.2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Expand(tt.target)
			if (err != nil) != tt.shouldError {
				t.Errorf("Expand() error = %v, shouldError %v", err, tt.shouldError)
				return
			}
			if !tt.shouldError && !compareStringSlices(got, tt.want) {
				t.Errorf("Expand() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExpandCIDR(t *testing.T) {
	tests := []struct {
		name        string
		cidr        string
		want        int // expected number of IPs
		shouldError bool
	}{
		{
			name: "Valid /24 CIDR",
			cidr: "192.168.1.0/24",
			want: 254, // network and broadcast are not hosts
		},
		{
			name: "Valid /30 CIDR",
			cidr: "192.168.1.0/30",
			want: 2, // network and broadcast are not hosts
		},
		{
			name: "Valid /31 CIDR",
			cidr: "192.168.1.0/31",
			want: 2, // a point-to-point link has no pair to exclude
		},
		{
			name: "Valid /32 CIDR",
			cidr: "192.168.1.1/32",
			want: 1,
		},
		{
			name:        "Invalid CIDR",
			cidr:        "192.168.1.1/33",
			shouldError: true,
		},
		{
			name:        "Invalid IP",
			cidr:        "256.168.1.0/24",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := expandCIDR(tt.cidr)
			if (err != nil) != tt.shouldError {
				t.Errorf("expandCIDR() error = %v, shouldError %v", err, tt.shouldError)
				return
			}
			if !tt.shouldError && len(got) != tt.want {
				t.Errorf("expandCIDR() returned %d IPs, want %d", len(got), tt.want)
			}
		})
	}
}

func TestExpandIPRange(t *testing.T) {
	tests := []struct {
		name        string
		rangeStr    string
		want        int // expected number of IPs
		shouldError bool
	}{
		{
			name:     "Valid Range",
			rangeStr: "192.168.1.1-5",
			want:     5,
		},
		{
			name:     "Single IP Range",
			rangeStr: "192.168.1.1-1",
			want:     1,
		},
		{
			name:        "Invalid Range Format",
			rangeStr:    "192.168.1.1-2-3",
			shouldError: true,
		},
		{
			name:        "Invalid Base IP",
			rangeStr:    "256.0.0.1-5",
			shouldError: true,
		},
		{
			name:        "Range End Less Than Start",
			rangeStr:    "192.168.1.100-50",
			shouldError: true,
		},
		{
			name:        "Range End Too Large",
			rangeStr:    "192.168.1.1-300",
			shouldError: true,
		},
		{
			name:        "Non-numeric Range End",
			rangeStr:    "192.168.0.0-ten",
			shouldError: true,
		},
		{
			name:     "Full IP Range",
			rangeStr: "10.10.10.0-10.10.10.2",
			want:     3,
		},
		{
			name:     "Full IP Range With CIDR Suffix",
			rangeStr: "10.10.10.0/24-10.10.10.2/24",
			want:     3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := expandIPRange(tt.rangeStr)
			if (err != nil) != tt.shouldError {
				t.Errorf("expandIPRange() error = %v, shouldError %v", err, tt.shouldError)
				return
			}
			if !tt.shouldError && len(got) != tt.want {
				t.Errorf("expandIPRange() returned %d IPs, want %d", len(got), tt.want)
			}
		})
	}
}

// Helper function to compare string slices
func compareStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestExpandCIDRNeverProbesTheBroadcastAddress(t *testing.T) {
	// An SNMP request to a broadcast address is delivered to every host on the
	// segment, so a credentialed probe aimed there hands the community to all
	// of them at once rather than to the one address being scanned. The
	// network address is excluded for the same reason it is everywhere else:
	// it is not a host.
	ips, err := Expand("192.168.1.0/24")
	if err != nil {
		t.Fatalf("Expand() error = %v", err)
	}

	for _, ip := range ips {
		if ip == "192.168.1.255" {
			t.Error("the broadcast address must never be probed")
		}
		if ip == "192.168.1.0" {
			t.Error("the network address is not a host")
		}
	}
	if len(ips) != 254 {
		t.Errorf("len = %d, want 254", len(ips))
	}
	if ips[0] != "192.168.1.1" {
		t.Errorf("first = %s, want 192.168.1.1", ips[0])
	}
	if ips[len(ips)-1] != "192.168.1.254" {
		t.Errorf("last = %s, want 192.168.1.254", ips[len(ips)-1])
	}
}

func TestExpandRangeKeepsEveryAddressTheOperatorWrote(t *testing.T) {
	// A range is an operator enumerating addresses rather than naming a
	// subnet, so someone who wrote .0 meant it. Only the CIDR form excludes.
	ips, err := Expand("192.168.1.0-192.168.1.255")
	if err != nil {
		t.Fatalf("Expand() error = %v", err)
	}

	if len(ips) != 256 {
		t.Errorf("len = %d, want 256", len(ips))
	}
	if ips[0] != "192.168.1.0" || ips[len(ips)-1] != "192.168.1.255" {
		t.Errorf("range must keep both endpoints, got %s..%s", ips[0], ips[len(ips)-1])
	}
}
