package policy

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/Ullaakut/nmap/v3"
	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nmap prints an asterisk for any character it will not pass, a space in a
// DNS label for one, and NetBox accepts an asterisk only as a leading
// wildcard label, so every character NetBox rejects becomes a hyphen, an
// asterisk included wherever it stands: nmap's asterisk never means a
// wildcard.
func TestDNSNameReplacesCharactersNetBoxRejects(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"ABC1234-Vendor*Model*Unit.example.net", "abc1234-vendor-model-unit.example.net"},
		{"host+name:with~odd=chars.example.net", "host-name-with-odd-chars.example.net"},
		{"host.*.example.net", "host.-.example.net"},
		{"*.example.net", "-.example.net"},
		{"**.example.net", "--.example.net"},
		{"plain_name-01.example.net.", "plain_name-01.example.net."},
	}
	for _, tc := range cases {
		got, ok := dnsName(tc.raw)
		require.True(t, ok, tc.raw)
		assert.Equal(t, tc.want, got, tc.raw)
	}
}

// A name with no form NetBox accepts is refused rather than guessed at: an
// empty label cannot be filled in, NetBox's field holds 255 characters, a
// trailing dot included, and a name left with no letter or digit is no
// name.
func TestDNSNameRefusesNamesWithNoAcceptableForm(t *testing.T) {
	longest := strings.Repeat("a", 243) + ".example.net" // 255 characters
	got, ok := dnsName(longest)
	require.True(t, ok)
	assert.Len(t, got, 255)
	for _, raw := range []string{"", "a..b", ".example.net", longest + "a", longest + ".", "*", "*.*", "-_-"} {
		_, ok := dnsName(raw)
		assert.False(t, ok, raw)
	}
}

func testRunner() *Runner {
	return &Runner{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// The PTR name wins. A replaced name is recorded as nmap gave it so the
// original is not lost, and only that name; a name that needed no change
// records nothing, so the comments of every IP already in NetBox stay as
// they are.
func TestApplyHostnamePrefersThePTRAndRecordsOnlyAnAlteredName(t *testing.T) {
	r := testRunner()
	ip := &diode.IPAddress{}
	outcome, recorded := r.applyHostname(ip, []nmap.Hostname{
		{Name: "abc1234-vendor*model*unit.example.net", Type: "PTR"},
		{Name: "other.example.net", Type: "user"},
	}, "192.0.2.10", "p", true)
	assert.Equal(t, hostnameReplaced, outcome)
	require.NotNil(t, ip.DnsName)
	assert.Equal(t, "abc1234-vendor-model-unit.example.net", *ip.DnsName)
	require.Len(t, recorded, 1)
	assert.Equal(t, "abc1234-vendor*model*unit.example.net", recorded[0].Name)
	assert.Equal(t, "PTR", recorded[0].Type)

	ip = &diode.IPAddress{}
	outcome, recorded = r.applyHostname(ip, []nmap.Hostname{{Name: "Clean-01.example.net", Type: "PTR"}}, "192.0.2.11", "p", true)
	assert.Equal(t, hostnameUnchanged, outcome)
	require.NotNil(t, ip.DnsName)
	assert.Equal(t, "clean-01.example.net", *ip.DnsName)
	assert.Empty(t, recorded)
}

// Without a PTR the last name nmap listed is used, as before.
func TestApplyHostnameFallsBackToTheLastName(t *testing.T) {
	ip := &diode.IPAddress{}
	testRunner().applyHostname(ip, []nmap.Hostname{{Name: "first.example.net", Type: "user"}, {Name: "Second.example.net", Type: "user"}}, "192.0.2.12", "p", true)
	require.NotNil(t, ip.DnsName)
	assert.Equal(t, "second.example.net", *ip.DnsName)
}

// A name with no acceptable form leaves dns_name off and is recorded; the
// address itself is still ingested.
func TestApplyHostnameLeavesAnUnusableNameOff(t *testing.T) {
	ip := &diode.IPAddress{}
	outcome, recorded := testRunner().applyHostname(ip, []nmap.Hostname{{Name: "bad..name.example.net", Type: "PTR"}}, "192.0.2.13", "p", true)
	assert.Equal(t, hostnameRefused, outcome)
	assert.Nil(t, ip.DnsName)
	require.Len(t, recorded, 1)
	assert.Equal(t, "bad..name.example.net", recorded[0].Name)
}

// When the policy sets its own comments there is nowhere to keep the raw
// name: nothing is recorded, and the outcome still says what happened so
// the run can report it.
func TestApplyHostnameRecordsNothingWhenCommentsAreThePolicys(t *testing.T) {
	ip := &diode.IPAddress{}
	outcome, recorded := testRunner().applyHostname(ip, []nmap.Hostname{{Name: "abc*unit.example.net", Type: "PTR"}}, "192.0.2.14", "p", false)
	assert.Equal(t, hostnameReplaced, outcome)
	require.NotNil(t, ip.DnsName)
	assert.Equal(t, "abc-unit.example.net", *ip.DnsName)
	assert.Nil(t, recorded)
}
