package profiles

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeProfile(filename string, oids ...string) *Profile {
	return &Profile{FileName: filename, SysObjectID: StringOrSlice(oids)}
}

func TestMatch_ExactOID(t *testing.T) {
	p := makeProfile("cisco.yml", "1.3.6.1.4.1.9.1.46")
	m := NewMatcher([]*Profile{p}, silentLogger)

	got, ok := m.Match("1.3.6.1.4.1.9.1.46")
	require.True(t, ok)
	assert.Equal(t, p, got)
}

func TestMatch_LeadingDotNormalized(t *testing.T) {
	p := makeProfile("cisco.yml", "1.3.6.1.4.1.9.1.46")
	m := NewMatcher([]*Profile{p}, silentLogger)

	got, ok := m.Match(".1.3.6.1.4.1.9.1.46")
	require.True(t, ok)
	assert.Equal(t, p, got)
}

func TestMatch_IsoPrefix(t *testing.T) {
	p := makeProfile("cisco.yml", "1.3.6.1.4.1.9.1.46")
	m := NewMatcher([]*Profile{p}, silentLogger)

	got, ok := m.Match("iso.1.3.6.1.4.1.9.1.46")
	require.True(t, ok)
	assert.Equal(t, p, got)
}

func TestMatch_WildcardOID(t *testing.T) {
	p := makeProfile("cisco.yml", "1.3.6.1.4.1.9.*")
	m := NewMatcher([]*Profile{p}, silentLogger)

	got, ok := m.Match("1.3.6.1.4.1.9.999.1")
	require.True(t, ok)
	assert.Equal(t, p, got)
}

func TestMatch_ExactWinsOverWildcard(t *testing.T) {
	generic := makeProfile("cisco-generic.yml", "1.3.6.1.4.1.9.*")
	specific := makeProfile("cisco-catalyst.yml", "1.3.6.1.4.1.9.1.46")
	m := NewMatcher([]*Profile{generic, specific}, silentLogger)

	got, ok := m.Match("1.3.6.1.4.1.9.1.46")
	require.True(t, ok)
	assert.Equal(t, specific, got)
}

func TestMatch_LongestWildcardWins(t *testing.T) {
	broad := makeProfile("vendor.yml", "1.3.6.1.4.1.9.*")
	narrow := makeProfile("series.yml", "1.3.6.1.4.1.9.1.*")
	m := NewMatcher([]*Profile{broad, narrow}, silentLogger)

	got, ok := m.Match("1.3.6.1.4.1.9.1.46")
	require.True(t, ok)
	assert.Equal(t, narrow, got, "most specific (longest) wildcard should win")
}

func TestMatch_NoMatch(t *testing.T) {
	p := makeProfile("cisco.yml", "1.3.6.1.4.1.9.1.46")
	m := NewMatcher([]*Profile{p}, silentLogger)

	_, ok := m.Match("1.3.6.1.4.1.8.1.1")
	assert.False(t, ok)
}

func TestMatch_ProfileWithoutOIDIgnored(t *testing.T) {
	base := makeProfile("base.yml") // no sysobjectid
	m := NewMatcher([]*Profile{base}, silentLogger)
	assert.Equal(t, 0, m.ProfileCount())
}

func TestMatch_MultipleOIDsOnProfile(t *testing.T) {
	p := makeProfile("multi.yml", "1.2.3.4", "1.2.3.5")
	m := NewMatcher([]*Profile{p}, silentLogger)

	for _, oid := range []string{"1.2.3.4", "1.2.3.5"} {
		got, ok := m.Match(oid)
		require.True(t, ok, "should match OID %s", oid)
		assert.Equal(t, p, got)
	}
}

func TestMatchWithDescr_NoMatchesSection(t *testing.T) {
	p := makeProfile("router.yml", "1.3.6.1.4.1.9.1.46")
	m := NewMatcher([]*Profile{p}, silentLogger)

	got, ok := m.MatchWithDescr("1.3.6.1.4.1.9.1.46", "Cisco IOS XE")
	require.True(t, ok)
	assert.Equal(t, p, got)
}

func TestMatchWithDescr_Redirect(t *testing.T) {
	base := &Profile{
		FileName:    "base.yml",
		SysObjectID: StringOrSlice{"1.3.6.1.4.1.9.*"},
		Matches:     map[string]string{"catalyst": "catalyst.yml"},
	}
	target := &Profile{FileName: "catalyst.yml"}
	m := NewMatcher([]*Profile{base, target}, silentLogger)

	got, ok := m.MatchWithDescr("1.3.6.1.4.1.9.1.46", "Cisco Catalyst 3750")
	require.True(t, ok)
	assert.Equal(t, target, got, "should redirect to catalyst.yml on sysDescr match")
}

func TestMatchWithDescr_RedirectCaseInsensitive(t *testing.T) {
	base := &Profile{
		FileName:    "base.yml",
		SysObjectID: StringOrSlice{"1.3.6.1.4.1.9.*"},
		Matches:     map[string]string{"catalyst": "catalyst.yml"},
	}
	target := &Profile{FileName: "catalyst.yml"}
	m := NewMatcher([]*Profile{base, target}, silentLogger)

	got, ok := m.MatchWithDescr("1.3.6.1.4.1.9.1.46", "CISCO CATALYST")
	require.True(t, ok)
	assert.Equal(t, target, got)
}

func TestMatchWithDescr_NoRedirectWhenDescrNoMatch(t *testing.T) {
	base := &Profile{
		FileName:    "base.yml",
		SysObjectID: StringOrSlice{"1.3.6.1.4.1.9.*"},
		Matches:     map[string]string{"catalyst": "catalyst.yml"},
	}
	target := &Profile{FileName: "catalyst.yml"}
	m := NewMatcher([]*Profile{base, target}, silentLogger)

	got, ok := m.MatchWithDescr("1.3.6.1.4.1.9.1.46", "Juniper EX4200")
	require.True(t, ok)
	assert.Equal(t, base, got, "unmatched sysDescr should return original profile")
}

func TestMatchWithDescr_EmptyDescrNoRedirect(t *testing.T) {
	base := &Profile{
		FileName:    "base.yml",
		SysObjectID: StringOrSlice{"1.3.6.1.4.1.9.*"},
		Matches:     map[string]string{"catalyst": "catalyst.yml"},
	}
	m := NewMatcher([]*Profile{base}, silentLogger)

	got, ok := m.MatchWithDescr("1.3.6.1.4.1.9.1.46", "")
	require.True(t, ok)
	assert.Equal(t, base, got)
}

func TestProfileCount(t *testing.T) {
	p1 := makeProfile("a.yml", "1.2.3", "1.2.4")
	p2 := makeProfile("b.yml", "1.3.*")
	m := NewMatcher([]*Profile{p1, p2}, silentLogger)
	assert.Equal(t, 3, m.ProfileCount()) // 2 exact + 1 wildcard
}

// net-snmp.yml carries "^Linux npa-publisher", an uppercase pattern that a
// case-sensitive compile can never match against a lowercased sysDescr. This
// drives the real bundled set, the same path a live device takes.
func TestMatchWithDescr_NetskopeRedirectRealBundle(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)
	all, err := l.AllResolved()
	require.NoError(t, err)
	m := NewMatcher(all, silentLogger)

	got, ok := m.MatchWithDescr("1.3.6.1.4.1.8072.3.2.10", "Linux npa-publisher 5.4.0 x86_64")
	require.True(t, ok)
	assert.Equal(t, "netskope/netskope-appliance.yml", got.RelPath)
}

// The bug lowercased only the subject, so an uppercase pattern could never
// match. The fix must work in both directions: an uppercase pattern against a
// lowercase subject, and a lowercase pattern against an uppercase subject.
func TestMatchWithDescr_CaseInsensitiveBothDirections(t *testing.T) {
	base := &Profile{
		FileName:    "base.yml",
		SysObjectID: StringOrSlice{"1.3.6.1.4.1.9.*"},
		Matches:     map[string]string{"Catalyst": "catalyst.yml"},
	}
	target := &Profile{FileName: "catalyst.yml"}
	m := NewMatcher([]*Profile{base, target}, silentLogger)

	got, ok := m.MatchWithDescr("1.3.6.1.4.1.9.1.46", "cisco catalyst 3750")
	require.True(t, ok)
	assert.Equal(t, target, got, "an uppercase pattern must match a lowercase subject")

	base2 := &Profile{
		FileName:    "base2.yml",
		SysObjectID: StringOrSlice{"1.3.6.1.4.1.10.*"},
		Matches:     map[string]string{"catalyst": "catalyst.yml"},
	}
	m2 := NewMatcher([]*Profile{base2, target}, silentLogger)

	got2, ok := m2.MatchWithDescr("1.3.6.1.4.1.10.1.46", "CISCO CATALYST 3750")
	require.True(t, ok)
	assert.Equal(t, target, got2, "a lowercase pattern must match an uppercase subject")
}

// Lowercasing the whole pattern string, rather than adding an inline (?i),
// would turn a class like [^A-Z] into [^a-z], which no longer excludes the
// same characters once matched case-insensitively against the raw subject.
func TestMatchWithDescr_CharacterClassPattern(t *testing.T) {
	base := &Profile{
		FileName:    "base.yml",
		SysObjectID: StringOrSlice{"1.3.6.1.4.1.9.*"},
		Matches:     map[string]string{`^[^A-Z]+$`: "digits-only.yml"},
	}
	target := &Profile{FileName: "digits-only.yml"}
	m := NewMatcher([]*Profile{base, target}, silentLogger)

	got, ok := m.MatchWithDescr("1.3.6.1.4.1.9.1.46", "12345")
	require.True(t, ok)
	assert.Equal(t, target, got, "a subject with no letters at all should redirect")

	got2, ok := m.MatchWithDescr("1.3.6.1.4.1.9.1.46", "abc123")
	require.True(t, ok)
	assert.Equal(t, base, got2, "a subject containing lowercase letters must not match [^A-Z] case-insensitively")
}

// A malformed operator pattern must be reported once, at construction, rather
// than silently dropped every time a device happens to hit that profile.
func TestNewMatcher_MalformedPatternLoggedOnce(t *testing.T) {
	base := &Profile{
		FileName:    "base.yml",
		RelPath:     "override/base.yml",
		SysObjectID: StringOrSlice{"1.3.6.1.4.1.9.*"},
		Matches:     map[string]string{"(unclosed": "somewhere.yml"},
	}

	logger, buf := captureLogger()
	m := NewMatcher([]*Profile{base}, logger)

	out := buf.String()
	assert.Contains(t, out, "override/base.yml")
	assert.Contains(t, out, "(unclosed")
	assert.Equal(t, 1, strings.Count(out, "\n"), "the malformed pattern must be reported exactly once")

	got, ok := m.MatchWithDescr("1.3.6.1.4.1.9.1.46", "anything")
	require.True(t, ok)
	assert.Equal(t, base, got, "a malformed pattern must be skipped, not cause a match")
}
