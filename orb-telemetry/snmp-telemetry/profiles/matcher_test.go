package profiles

import (
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
