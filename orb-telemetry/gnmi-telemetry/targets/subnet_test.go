package targets

import (
	"strings"
	"testing"
	"time"
)

// A CIDR names a subnet, so its network and broadcast addresses are not hosts.
// A range is an operator enumerating addresses, so every one they wrote is kept.
// The two forms therefore disagree on the same address set, deliberately.
func TestExpandPrefixExcludesNetworkAndBroadcast(t *testing.T) {
	tests := []struct {
		target string
		want   int
	}{
		{"10.0.0.0/24", 254},
		{"10.0.0.0/23", 510},
		{"10.0.0.0/22", 1022},
		{"10.0.0.0/30", 2},
		{"10.0.0.0/31", 2},
		{"10.0.0.5/32", 1},
		// A range keeps what the operator wrote, including .0 and .255.
		{"10.0.0.0-255", 256},
	}
	for _, tt := range tests {
		got, err := Expand(tt.target)
		if err != nil {
			t.Errorf("Expand(%q) returned error: %v", tt.target, err)
			continue
		}
		if len(got) != tt.want {
			t.Errorf("Expand(%q) = %d addresses, want %d", tt.target, len(got), tt.want)
		}
	}
}

func TestExpandPrefixDropsTheRightAddresses(t *testing.T) {
	got, err := Expand("10.0.0.0/30")
	if err != nil {
		t.Fatalf("Expand returned error: %v", err)
	}
	want := []string{"10.0.0.1", "10.0.0.2"}
	if len(got) != len(want) {
		t.Fatalf("Expand = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Expand[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// A /31 and /32 have no network/broadcast pair to strip. Stripping anyway drives
// endVal below startVal, and the original post-test loop then wraps uint32 and
// appends ~4.29 billion entries. host: 10.0.0.5/32 is the most ordinary config
// an operator writes, so this is an OOM reachable from a single policy line.
func TestExpandDoesNotRunAwayOnSmallPrefixes(t *testing.T) {
	for _, target := range []string{
		"10.0.0.5/32",
		"10.0.0.4/31",
		// The top of the address space is the second runaway class: a pre-test
		// loop written in uint32 never terminates here, because val++ wraps
		// past endVal = MaxUint32.
		"255.255.255.255/32",
		"255.255.255.254/31",
	} {
		done := make(chan int, 1)
		go func() {
			ips, err := Expand(target)
			if err != nil {
				done <- -1
				return
			}
			done <- len(ips)
		}()
		select {
		case n := <-done:
			if n < 0 {
				t.Errorf("Expand(%q) returned an error, want addresses", target)
			}
			if n > 2 {
				t.Errorf("Expand(%q) = %d addresses, want at most 2", target, n)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("Expand(%q) did not terminate: runaway loop", target)
		}
	}
}

// Count must agree with Expand for every form, because it is the only thing
// standing between a policy save and enumerating a /8. If they can drift, the
// cap is enforced against a different interpretation than the one used.
func TestCountAgreesWithExpand(t *testing.T) {
	for _, target := range []string{
		"10.0.0.0/24", "10.0.0.0/23", "10.0.0.0/30", "10.0.0.0/31", "10.0.0.5/32",
		"255.255.255.255/32", "255.255.255.254/31",
		"10.0.0.1-5", "10.0.0.0-255", "10.0.0.1-10.0.0.9",
		"10.0.0.5", "switch-a.example.com",
	} {
		n, err := Count(target)
		if err != nil {
			t.Errorf("Count(%q) returned error: %v", target, err)
			continue
		}
		ips, err := Expand(target)
		if err != nil {
			t.Errorf("Expand(%q) returned error: %v", target, err)
			continue
		}
		if n != uint64(len(ips)) {
			t.Errorf("Count(%q) = %d, but Expand yielded %d", target, n, len(ips))
		}
	}
}

// Count must answer without enumerating, or it cannot protect against the very
// input it exists to reject.
func TestCountDoesNotEnumerate(t *testing.T) {
	done := make(chan struct{})
	var got uint64
	var err error
	go func() {
		got, err = Count("10.0.0.0/8")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Count(10.0.0.0/8) took over 100ms: it is enumerating")
	}
	if err != nil {
		t.Fatalf("Count returned error: %v", err)
	}
	if got != 16777214 {
		t.Errorf("Count(10.0.0.0/8) = %d, want 16777214", got)
	}
}

func TestCountRejectsWhatExpandRejects(t *testing.T) {
	for _, target := range []string{"2001:db8::/64", "10.0.0.0/33", "10.0.0.1-300"} {
		if _, err := Count(target); err == nil {
			t.Errorf("Count(%q) = nil error, want an error", target)
		}
	}
}

// A /64 is the standard IPv6 subnet and is not enumerable. The error has to say
// that rather than "only IPv4 supported", which reads as an arbitrary limit.
func TestExpandRejectsIPv6PrefixWithAReasonAboutSize(t *testing.T) {
	_, err := Expand("2001:db8::/64")
	if err == nil {
		t.Fatal("Expand(2001:db8::/64) = nil error, want an error")
	}
	if !strings.Contains(err.Error(), "enumerat") {
		t.Errorf("error %q does not explain that the prefix is not enumerable", err)
	}
}

// Expand carries its own cap even though the policy layer checks Count first.
// The runner is the only enumerator now, so a caller that forgets the check
// must not be able to allocate its way to an OOM.
func TestExpandRefusesMoreThanMaxExpand(t *testing.T) {
	if _, err := Expand("10.0.0.0/8"); err == nil {
		t.Fatal("Expand(10.0.0.0/8) = nil error, want a cap error")
	}
	// A /22 is 1022 hosts and must still be allowed: it is the largest prefix
	// under the cap, and the cap exists to stop /8, not to stop a campus.
	got, err := Expand("10.0.0.0/22")
	if err != nil {
		t.Fatalf("Expand(10.0.0.0/22) returned error: %v", err)
	}
	if len(got) != 1022 {
		t.Errorf("Expand(10.0.0.0/22) = %d addresses, want 1022", len(got))
	}
}

// An IPv6 zone is an interface name and may contain a hyphen — br-lan and
// veth-* are ordinary. The range heuristic read the colon and the hyphen as
// range syntax and failed the whole policy with "only IPv4 addresses are
// supported", for an endpoint ensurePort goes out of its way to bracket.
func TestZonedIPv6WithAHyphenInTheZoneIsOneEndpoint(t *testing.T) {
	for _, target := range []string{
		"fe80::1%eth-0",
		"fe80::1%br-lan",
		"fe80::1%veth-abc123",
		"fe80::1%eth0", // unchanged: no hyphen at all
	} {
		if !IsSingleEndpoint(target) {
			t.Errorf("IsSingleEndpoint(%q) = false, want true", target)
		}
		n, err := Count(target)
		if err != nil {
			t.Errorf("Count(%q) returned error: %v", target, err)
			continue
		}
		if n != 1 {
			t.Errorf("Count(%q) = %d, want 1", target, n)
		}
		got, err := Expand(target)
		if err != nil {
			t.Errorf("Expand(%q) returned error: %v", target, err)
			continue
		}
		if len(got) != 1 || got[0] != target {
			t.Errorf("Expand(%q) = %v, want [%q]", target, got, target)
		}
	}
}

// A real range is still a range, and an IPv6 range is still refused: the fix
// exempts complete addresses, not anything containing a colon and a hyphen.
func TestTheRangeHeuristicStillCatchesRealRanges(t *testing.T) {
	for _, target := range []string{"10.0.0.1-10", "10.0.0.1-10.0.0.9", "10.0.0.0-255"} {
		if IsSingleEndpoint(target) {
			t.Errorf("IsSingleEndpoint(%q) = true, want false", target)
		}
	}
	// An IPv6 range does not parse as one address, so it still reaches the range
	// branch and is refused there.
	if _, err := Count("2001:db8::1-5"); err == nil {
		t.Error("Count(2001:db8::1-5) = nil error, want an error")
	}
}

// Span, Count and Expand must agree about a mapped IPv4 literal, since the cap
// is enforced with Span and the endpoints come from Expand.
func TestMappedIPv4LiteralIsOneEnumerableAddress(t *testing.T) {
	const target = "::ffff:10.0.0.1"

	start, end, enumerable, err := Span(target)
	if err != nil {
		t.Fatalf("Span(%q) returned error: %v", target, err)
	}
	if !enumerable {
		t.Errorf("Span(%q) enumerable = false, want true: it is an IPv4 address", target)
	}
	if start != end {
		t.Errorf("Span(%q) = [%d,%d], want a one-element span", target, start, end)
	}
	// It occupies the same slot as the plain form, which is what lets it merge
	// into a subnet containing that address.
	plainStart, _, _, err := Span("10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if start != plainStart {
		t.Errorf("Span(%q) start = %d, want %d (the plain address)", target, start, plainStart)
	}

	n, err := Count(target)
	if err != nil || n != 1 {
		t.Errorf("Count(%q) = %d, %v; want 1, nil", target, n, err)
	}
	got, err := Expand(target)
	if err != nil || len(got) != 1 {
		t.Errorf("Expand(%q) = %v, %v; want one address", target, got, err)
	}
}

// A real IPv6 address is still not enumerable: it is one endpoint that cannot be
// compared with an IPv4 span.
func TestARealIPv6LiteralIsNotEnumerable(t *testing.T) {
	_, _, enumerable, err := Span("2001:db8::1")
	if err != nil {
		t.Fatalf("Span returned error: %v", err)
	}
	if enumerable {
		t.Error("Span(2001:db8::1) enumerable = true, want false")
	}
}
