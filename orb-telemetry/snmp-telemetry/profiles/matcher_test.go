package profiles

import (
	"bytes"
	"log/slog"
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

// A bundled profile writes its wildcard as "43.45*", with no dot in front of
// the star. ktranslate resolves a sysObjectID by probing successively shorter
// "<prefix>.*" keys, so a star only ever stands for whole arcs below prefix.
// The pattern therefore selects the subtree under 43.45, and reading the
// trailing star as part of an exact OID left the profile unreachable.
func TestMatch_WildcardWithoutDotBeforeStar(t *testing.T) {
	p := makeProfile("3com-huawei.yml", "1.3.6.1.4.1.43.45*")
	m := NewMatcher([]*Profile{p}, silentLogger)

	got, ok := m.Match("1.3.6.1.4.1.43.45.1.6.1.1")
	require.True(t, ok, "the subtree under 43.45 must reach the profile")
	assert.Equal(t, p, got)

	_, ok = m.Match("1.3.6.1.4.1.43.450.1")
	assert.False(t, ok, "the star stands for whole arcs, so 43.450 is a different arc")

	_, ok = m.Match("1.3.6.1.4.1.43.4")
	assert.False(t, ok, "an OID above the subtree is outside it")
}

// The two spellings select the same subtree, so they have to land on one index
// key. Kept apart they would produce two entries of equal prefix, whichever
// won decided by the sort rather than by the collision report.
func TestNewMatcher_DotlessAndDottedWildcardShareOneKey(t *testing.T) {
	dotted := &Profile{FileName: "dotted.yml", RelPath: "v/dotted.yml", SysObjectID: StringOrSlice{"1.2.3.*"}}
	dotless := &Profile{FileName: "dotless.yml", RelPath: "v/dotless.yml", SysObjectID: StringOrSlice{"1.2.3*"}}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	m := NewMatcher([]*Profile{dotted, dotless}, logger)

	assert.Equal(t, 1, m.ProfileCount(), "both spellings select one subtree")
	got, ok := m.Match("1.2.3.4")
	require.True(t, ok)
	assert.Equal(t, dotted, got, "the first profile indexed serves the shared key")

	out := buf.String()
	assert.Contains(t, out, "duplicate sysobjectid", "the two spellings must collide on one key")
	assert.Contains(t, out, "1.2.3.*", "the collision must be reported under the dotted spelling")
	assert.Contains(t, out, "v/dotless.yml", "the losing profile must be named")
}

// Longest prefix still decides. A repaired dotless wildcard must not outrank a
// wildcard that describes the device more precisely.
func TestMatch_DotlessWildcardKeepsLongestPrefixOrder(t *testing.T) {
	broad := makeProfile("vendor.yml", "1.2.3*")
	narrow := makeProfile("series.yml", "1.2.3.4.*")
	m := NewMatcher([]*Profile{broad, narrow}, silentLogger)

	got, ok := m.Match("1.2.3.4.5")
	require.True(t, ok)
	assert.Equal(t, narrow, got, "the more specific wildcard must win")

	got, ok = m.Match("1.2.3.9.5")
	require.True(t, ok)
	assert.Equal(t, broad, got, "an arc the narrow wildcard does not cover stays with the broad one")

	exact := makeProfile("one-box.yml", "1.2.3.4.5")
	m2 := NewMatcher([]*Profile{broad, exact}, silentLogger)
	got, ok = m2.Match("1.2.3.4.5")
	require.True(t, ok)
	assert.Equal(t, exact, got, "an exact entry must still beat the repaired wildcard")
}

// The star is only a wildcard at the end of the pattern. Anywhere else there
// is no prefix to match on, so the entry can never match a device and the
// operator is told rather than left waiting for metrics.
func TestNewMatcher_StarThatIsNotATrailingWildcard(t *testing.T) {
	for _, pattern := range []string{"1.2.*.4", "1.2.*.4*", "*"} {
		assert.True(t, unindexableSysObjectID(pattern), "%s reaches neither index", pattern)

		m := NewMatcher([]*Profile{makeProfile("odd.yml", pattern)}, silentLogger)
		for _, oid := range []string{"1.2.3.4", "1.2.3.4.5", "1.2"} {
			_, ok := m.Match(oid)
			assert.False(t, ok, "%s must not match %s", pattern, oid)
		}
	}

	assert.False(t, unindexableSysObjectID("1.2.3.*"), "a trailing wildcard is indexable")
	assert.False(t, unindexableSysObjectID("1.2.3*"), "so is one written without the dot")
	assert.False(t, unindexableSysObjectID("1.2.3.4"), "and so is an exact OID")
}

// The bundled 3com/Huawei profile carries the one dotless wildcard in the set.
// Every metric it declares was unreachable, and the devices it describes fell
// through to the generic catch-all.
func TestMatch_BundledDotlessWildcardIsReachable(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)
	all, err := l.AllResolved()
	require.NoError(t, err)
	m := NewMatcher(all, silentLogger)

	got, ok := m.Match("1.3.6.1.4.1.43.45.1.6.1.1")
	require.True(t, ok)
	assert.Equal(t, "3com/3com-huawei.yml", got.RelPath)

	// Neighbours that must not move.
	for oid, want := range map[string]string{
		"1.3.6.1.4.1.43.450.1":   "generic/base.yml",
		"1.3.6.1.4.1.43.451":     "generic/base.yml",
		"1.3.6.1.4.1.43.4":       "generic/base.yml",
		"1.3.6.1.4.1.43":         "generic/base.yml",
		"1.3.6.1.4.1.43.1.8.1":   "3com/3com.yml",
		"1.3.6.1.4.1.43356.1":    "mimosa/mimosa-device.yml",
		"1.3.6.1.4.1.2011.2.1.1": "huawei/huawei-all-devices.yml",
	} {
		got, ok := m.Match(oid)
		require.True(t, ok, "%s must still match", oid)
		assert.Equal(t, want, got.RelPath, "the verdict for %s must not move", oid)
	}
}

// A longest-prefix match only changes its verdict for OIDs under the prefix
// that became reachable, so it is enough to show nothing more specific already
// claims that subtree and to name the profile it is taken from.
func TestMatcher_BundledDotlessWildcardTakesOnlyFromLessSpecific(t *testing.T) {
	const subtree = "1.3.6.1.4.1.43.45."

	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)
	all, err := l.AllResolved()
	require.NoError(t, err)
	m := NewMatcher(all, silentLogger)

	var covering wildcardEntry
	for _, e := range m.wildcardIndex {
		if e.prefix == subtree {
			continue
		}
		assert.False(t, strings.HasPrefix(e.prefix, subtree),
			"no bundled wildcard may sit inside the subtree that became reachable")
		if strings.HasPrefix(subtree, e.prefix) && len(e.prefix) > len(covering.prefix) {
			covering = e
		}
	}
	for oid := range m.exactIndex {
		assert.False(t, strings.HasPrefix(oid, subtree),
			"no bundled exact entry may sit inside the subtree that became reachable")
	}

	require.NotNil(t, covering.profile, "the subtree has to have been served by something")
	assert.Equal(t, "generic/base.yml", covering.profile.RelPath,
		"only the generic catch-all loses devices to the repaired profile")
}

// Every bundled sysobjectid has to reach the index. One that does not is a
// profile the collector loads, reports on and can never match.
func TestNewMatcher_BundledSysObjectIDsAreAllIndexable(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)
	all, err := l.AllResolved()
	require.NoError(t, err)

	for _, p := range all {
		for _, raw := range p.SysObjectID {
			assert.False(t, unindexableSysObjectID(normalizeOID(raw)),
				"%s in %s cannot be indexed", raw, p.RelPath)
		}
	}
}

// unresolvableRedirectMsg is the report an operator sees for a `matches` entry
// whose destination file is not among the loaded profiles.
const unresolvableRedirectMsg = "SNMP profile matches redirect names a profile that is not loaded"

// warnLinesMentioning returns the captured log lines carrying msg.
func warnLinesMentioning(out, msg string) []string {
	var found []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, msg) {
			found = append(found, line)
		}
	}
	return found
}

// A `matches` entry naming a file no loaded profile carries can never redirect
// anything. The device keeps collecting the original profile's symbols instead
// of the ones it was sent to, so without a report at construction the policy
// stays healthy while gathering the wrong metrics.
func TestNewMatcher_UnresolvableRedirectReported(t *testing.T) {
	base := &Profile{
		FileName:    "base.yml",
		RelPath:     "vendor/base.yml",
		SysObjectID: StringOrSlice{"1.3.6.1.4.1.9.*"},
		Matches:     map[string]string{"^single phase": "vendor-ups.yml"},
	}

	logger, buf := captureLogger()
	m := NewMatcher([]*Profile{base}, logger)

	lines := warnLinesMentioning(buf.String(), unresolvableRedirectMsg)
	require.Len(t, lines, 1, "an unresolvable redirect must be reported exactly once")
	assert.Contains(t, lines[0], "vendor/base.yml", "the report must name the profile that declares the redirect")
	assert.Contains(t, lines[0], "^single phase", "the report must name the pattern")
	assert.Contains(t, lines[0], "vendor-ups.yml", "the report must name the file it cannot find")

	// Reporting must not change what a matching device collects: the original
	// profile still serves it, which is what upstream does too.
	got, ok := m.MatchWithDescr("1.3.6.1.4.1.9.1.46", "Single Phase 1Gb UPS")
	require.True(t, ok)
	assert.Equal(t, base, got, "an unresolvable redirect still returns the original profile")
}

// The report must fire on the destination being absent, not on every profile
// that declares a `matches` section.
func TestNewMatcher_ResolvableRedirectNotReported(t *testing.T) {
	base := &Profile{
		FileName:    "base.yml",
		RelPath:     "vendor/base.yml",
		SysObjectID: StringOrSlice{"1.3.6.1.4.1.9.*"},
		Matches:     map[string]string{"^single phase": "vendor-ups.yml"},
	}
	target := &Profile{FileName: "vendor-ups.yml", RelPath: "vendor/vendor-ups.yml"}

	logger, buf := captureLogger()
	m := NewMatcher([]*Profile{base, target}, logger)

	assert.Empty(t, warnLinesMentioning(buf.String(), unresolvableRedirectMsg),
		"a redirect whose destination is loaded must not be reported")

	got, ok := m.MatchWithDescr("1.3.6.1.4.1.9.1.46", "Single Phase 1Gb UPS")
	require.True(t, ok)
	assert.Equal(t, target, got, "a resolvable redirect still redirects")
}

// A profile can declare several redirects, and only the ones that cannot
// resolve belong in the report.
func TestNewMatcher_OnlyUnresolvableRedirectsOfAProfileReported(t *testing.T) {
	base := &Profile{
		FileName:    "base.yml",
		RelPath:     "vendor/base.yml",
		SysObjectID: StringOrSlice{"1.3.6.1.4.1.9.*"},
		Matches: map[string]string{
			"^single phase": "vendor-ups.yml",
			"^switch":       "vendor-switch.yml",
		},
	}
	target := &Profile{FileName: "vendor-switch.yml", RelPath: "vendor/vendor-switch.yml"}

	logger, buf := captureLogger()
	NewMatcher([]*Profile{base, target}, logger)

	lines := warnLinesMentioning(buf.String(), unresolvableRedirectMsg)
	require.Len(t, lines, 1, "only the redirect whose destination is missing is reported")
	assert.Contains(t, lines[0], "vendor-ups.yml")
	assert.NotContains(t, lines[0], "vendor-switch.yml")
}

// The bundled tree is vendored verbatim from upstream, and one of its profiles
// names a destination that upstream never shipped. Every unresolvable redirect
// it carries has to be reported. The expectation is computed from the tree
// itself rather than hard-coded, so a later upstream sync that adds the missing
// file leaves this passing; only our reporting going quiet fails it.
func TestNewMatcher_BundledUnresolvableRedirectsAreReported(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)
	all, err := l.AllResolved()
	require.NoError(t, err)

	loaded := make(map[string]bool, len(all))
	for _, p := range all {
		loaded[p.FileName] = true
	}
	type redirect struct{ relPath, pattern, target string }
	var unresolvable []redirect
	for _, p := range all {
		for pattern, target := range p.Matches {
			if !loaded[target] {
				unresolvable = append(unresolvable, redirect{p.RelPath, pattern, target})
			}
		}
	}

	logger, buf := captureLogger()
	NewMatcher(all, logger)

	lines := warnLinesMentioning(buf.String(), unresolvableRedirectMsg)
	assert.Len(t, lines, len(unresolvable),
		"every unresolvable bundled redirect is reported, and nothing else is")
	for _, r := range unresolvable {
		var matched bool
		for _, line := range lines {
			if strings.Contains(line, r.relPath) && strings.Contains(line, r.pattern) && strings.Contains(line, r.target) {
				matched = true
				break
			}
		}
		assert.True(t, matched, "no report names %s -> %s in %s", r.pattern, r.target, r.relPath)
	}
}
