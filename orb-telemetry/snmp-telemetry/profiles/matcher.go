package profiles

import (
	"log/slog"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// wildcardEntry holds a wildcard prefix pattern and its associated profile.
type wildcardEntry struct {
	prefix  string // e.g. "1.3.6.1.4.1.9." (OID up to but not including the "*")
	profile *Profile
}

// matchRedirect is one compiled redirect entry, from either `matches` or
// `matches_list`: a sysDescr pattern and the profile it redirects to.
type matchRedirect struct {
	re   *regexp.Regexp
	file string
}

// Matcher matches a device sysObjectID (and optionally sysDescr) to a Profile.
type Matcher struct {
	exactIndex    map[string]*Profile          // normalized OID -> profile (exact matches)
	wildcardIndex []wildcardEntry              // sorted longest-prefix-first for wildcard matches
	profileByFile map[string]*Profile          // filename -> profile (for sysDescr redirects)
	redirects     map[*Profile][]matchRedirect // profile -> compiled redirect patterns, in evaluation order
}

// keyClaims holds every profile claiming one index key, in the order the
// profiles were indexed.
type keyClaims []*Profile

// kept is the profile that serves the key.
func (c keyClaims) kept() *Profile {
	return c.pick(func(*Profile) bool { return true })
}

// bundled is the profile that would serve the key if the override directory
// held nothing.
func (c keyClaims) bundled() *Profile {
	return c.pick(func(p *Profile) bool { return p.Origin != OriginOverride })
}

// bundledOrReplacement is bundled, widened to accept an override that replaces
// a bundled profile at that profile's own path. Such a file carries the
// replaced profile's basename by definition, so on a basename key it stands in
// for that profile rather than competing with it. It inherits no sysobjectid:
// an OID it declares that a different bundled profile owns is taken from that
// profile, which is the operator's to fix.
func (c keyClaims) bundledOrReplacement() *Profile {
	return c.pick(func(p *Profile) bool {
		return p.Origin != OriginOverride || p.ReplacesBundled
	})
}

// pick applies the tiebreak across the claimants that keep accepts. An
// override-directory profile beats a bundled one, since overriding is what the
// operator asked for; otherwise the first one indexed wins, which is stable as
// long as the input order is.
func (c keyClaims) pick(keep func(*Profile) bool) *Profile {
	var best *Profile
	for _, p := range c {
		if !keep(p) {
			continue
		}
		if best == nil || (p.Origin == OriginOverride && best.Origin != OriginOverride) {
			best = p
		}
	}
	return best
}

// NewMatcher builds a Matcher from a list of fully-resolved profiles.
// Profiles without any sysobjectid entries are ignored (they are base/inherited profiles).
//
// Two profiles can claim the same sysObjectID, exact or wildcard, or the same
// basename that a `matches` redirect names. keyClaims resolves those and
// reportShadowed reports the ones an operator can act on. Pass profiles in a
// stable order (Loader.AllResolved sorts them) so a tie between two profiles of
// the same origin does not move between restarts.
//
// Each sysDescr redirect a profile declares, under either `matches_list` or
// `matches`, is compiled and its destination looked up here, so a pattern that
// cannot compile and one naming a file no profile carries are both reported
// once rather than per poll. Neither fails the load: the bundled set
// already ships an unresolvable one, and the operator-facing case is a typo in
// an override, which should degrade rather than take the backend down at
// startup.
func NewMatcher(profiles []*Profile, logger *slog.Logger) *Matcher {
	byBase := make(map[string]keyClaims)
	byExact := make(map[string]keyClaims)
	byWildcard := make(map[string]keyClaims)

	for _, p := range profiles {
		byBase[p.FileName] = append(byBase[p.FileName], p)
		for _, raw := range p.SysObjectID {
			oid := normalizeOID(raw)
			if key, ok := wildcardKey(oid); ok {
				byWildcard[key] = append(byWildcard[key], p)
			} else {
				byExact[oid] = append(byExact[oid], p)
			}
		}
	}

	reportShadowed(byBase, logger, "basename", keyClaims.bundledOrReplacement)
	reportShadowed(byExact, logger, "sysobjectid", keyClaims.bundled)
	reportShadowed(byWildcard, logger, "sysobjectid", keyClaims.bundled)

	m := &Matcher{
		exactIndex:    make(map[string]*Profile, len(byExact)),
		profileByFile: make(map[string]*Profile, len(byBase)),
		wildcardIndex: make([]wildcardEntry, 0, len(byWildcard)),
	}
	for base, claims := range byBase {
		m.profileByFile[base] = claims.kept()
	}
	for oid, claims := range byExact {
		m.exactIndex[oid] = claims.kept()
	}
	for oid, claims := range byWildcard {
		m.wildcardIndex = append(m.wildcardIndex, wildcardEntry{
			prefix:  strings.TrimSuffix(oid, "*"),
			profile: claims.kept(),
		})
	}
	// Longest prefix first so the most specific wildcard wins. Prefixes of
	// equal length are ordered by value: the slice is built by ranging a map,
	// so without that second key a tie would land differently on each restart.
	slices.SortFunc(m.wildcardIndex, func(a, b wildcardEntry) int {
		if len(a.prefix) != len(b.prefix) {
			return len(b.prefix) - len(a.prefix)
		}
		return strings.Compare(a.prefix, b.prefix)
	})

	m.redirects = make(map[*Profile][]matchRedirect)
	for _, p := range profiles {
		var compiled []matchRedirect
		for _, decl := range declaredRedirects(p) {
			pattern, target := decl.pattern, decl.target
			re, err := regexp.Compile("(?i)" + pattern)
			if err != nil {
				if logger != nil {
					logger.Warn("SNMP profile matches pattern is invalid, redirect disabled",
						"profile", p.RelPath, "pattern", pattern, "error", err)
				}
				continue
			}
			// A destination no loaded profile carries can never be reached, so
			// a device the pattern describes silently keeps collecting this
			// profile's symbols instead of the ones it was sent to. Reporting
			// it here names it once, and names one no device has matched yet;
			// reporting at match time would repeat the line every poll cycle.
			// The redirect is left in place: upstream ktranslate also falls
			// back to the declaring profile, and dropping the device instead
			// would stop collecting from it altogether.
			if _, found := m.profileByFile[target]; !found && logger != nil {
				logger.Warn("SNMP profile matches redirect names a profile that is not loaded",
					"profile", p.RelPath, "pattern", pattern, "target", target)
			}
			compiled = append(compiled, matchRedirect{re: re, file: target})
		}
		if len(compiled) > 0 {
			m.redirects[p] = compiled
		}
	}

	return m
}

// redirectSource is one sysDescr redirect a profile declares, before its
// pattern is compiled.
type redirectSource struct {
	pattern string
	target  string
}

// declaredRedirects returns a profile's sysDescr redirects in the order they
// are evaluated: every `matches_list` entry in the order the file writes it,
// then the `matches` map by sorted pattern.
//
// The list comes first because it is the form that carries an order, and a
// profile writes it precisely when more than one of its patterns can match one
// sysDescr. Upstream evaluates it first for that reason, so a profile carrying
// both forms resolves to the list's target either way.
//
// The map has no order of its own, so its patterns are sorted here rather than
// ranged: ranging a map would settle a profile whose sysDescr satisfies two
// patterns differently on each restart.
func declaredRedirects(p *Profile) []redirectSource {
	out := make([]redirectSource, 0, len(p.MatchesList)+len(p.Matches))
	for _, entry := range p.MatchesList {
		out = append(out, redirectSource{pattern: entry.Regex, target: entry.Target})
	}
	for _, pattern := range slices.Sorted(maps.Keys(p.Matches)) {
		out = append(out, redirectSource{pattern: pattern, target: p.Matches[pattern]})
	}
	return out
}

// reportShadowed warns about keys a profile added under the override directory
// took from the profile that would otherwise have served them, which is the
// operator's to fix. Everything else is logged at debug level: the bundled set
// itself ships nine files named traps.yml, and comparing origins pairwise
// warned once per losing sibling, so correctly overriding one of them produced
// eight warnings naming vendors the operator never touched.
//
// baseline picks the claimant the warning measures against, which differs by
// index: see bundled and bundledOrReplacement.
func reportShadowed(claims map[string]keyClaims, logger *slog.Logger, kind string, baseline func(keyClaims) *Profile) {
	if logger == nil {
		return
	}
	for _, key := range slices.Sorted(maps.Keys(claims)) {
		c := claims[key]
		if len(c) < 2 {
			continue
		}
		kept, bundled := c.kept(), baseline(c)
		// Every claimant the message does not name in its own field. A key can
		// draw more than two, and naming only the shadowed one left the rest
		// out of both branches.
		ignoring := make([]string, 0, len(c)-1)
		for _, p := range c {
			if p != kept && p != bundled {
				ignoring = append(ignoring, p.RelPath)
			}
		}
		if bundled != nil && bundled != kept {
			attrs := []any{kind, key, "using", kept.RelPath, "instead_of", bundled.RelPath}
			if len(ignoring) > 0 {
				attrs = append(attrs, "ignoring", ignoring)
			}
			logger.Warn("SNMP profile shadows the one that would have served this key", attrs...)
			continue
		}
		logger.Debug("duplicate "+kind+" across SNMP profiles",
			kind, key, "using", kept.RelPath, "ignoring", ignoring)
	}
}

// Match returns the best-matching profile for the given device sysObjectID.
// Exact matches take priority over wildcard matches. Among wildcards, the longest prefix wins.
// Use MatchWithDescr when sysDescr is also available to support redirect profiles.
func (m *Matcher) Match(deviceSysOID string) (*Profile, bool) {
	normalized := normalizeOID(deviceSysOID)

	// Exact match
	if p, ok := m.exactIndex[normalized]; ok {
		return p, true
	}

	// Wildcard match (first entry is the longest/most-specific prefix)
	for _, entry := range m.wildcardIndex {
		if strings.HasPrefix(normalized, entry.prefix) {
			return entry.profile, true
		}
	}

	return nil, false
}

// MatchWithDescr returns the best-matching profile using both sysObjectID and sysDescr.
// If the OID-matched profile declares sysDescr redirects, the sysDescr is tested against
// each pattern (case-insensitive, compiled once in NewMatcher) in the order
// declaredRedirects fixes, and the first matching pattern's profile is returned instead.
// This mirrors how ktranslate handles devices that share a sysOID but differ by
// description.
func (m *Matcher) MatchWithDescr(deviceSysOID, sysDescr string) (*Profile, bool) {
	profile, ok := m.Match(deviceSysOID)
	if !ok {
		return nil, false
	}
	redirects, hasRedirects := m.redirects[profile]
	if !hasRedirects || sysDescr == "" {
		return profile, true
	}

	// The winner is the first declared redirect whose pattern matches and whose
	// target is loaded, not simply the first whose pattern matches. A matched
	// entry naming a target no profile carries is passed over and the next
	// entry is tried, which is what upstream ktranslate does: its checkMatch
	// logs the missing target and continues the loop rather than returning.
	//
	// Passing over it is also the more useful of the two readings. The
	// alternative, treating the first matched entry as decisive, would hand the
	// device the declaring profile's generic symbols instead of a redirect the
	// operator also declared and which resolves. The unresolved target is not
	// lost either way: NewMatcher reports it once at load, naming the profile,
	// the pattern and the file.
	for _, r := range redirects {
		if !r.re.MatchString(sysDescr) {
			continue
		}
		if redirectProfile, found := m.profileByFile[r.file]; found {
			return redirectProfile, true
		}
	}

	// No redirect matched, or every matched one named a target that is not
	// loaded, so the declaring profile serves.
	return profile, true
}

// ProfileCount returns the total number of indexed OID entries (exact + wildcard).
func (m *Matcher) ProfileCount() int {
	return len(m.exactIndex) + len(m.wildcardIndex)
}

// wildcardKey returns the canonical form of a wildcard sysobjectid, and
// reports whether the pattern is a wildcard the index can carry.
//
// ktranslate resolves a device sysObjectID by probing its profile map with
// successively shorter "<prefix>.*" keys, so a star only ever stands for whole
// arcs below prefix. A pattern written without the dot, "1.3.6.1.4.1.43.45*",
// therefore selects the subtree under 1.3.6.1.4.1.43.45 rather than every arc
// whose digits start with 45, and canonicalising it here puts both spellings
// on one key. Upstream does not read the dotless form at all: no probe it
// builds can produce that key, so the profile is unreachable there too.
//
// A star anywhere but at the end, or one with no OID in front of it, leaves
// nothing to match a prefix against. Those are not wildcards, and
// unindexableSysObjectID names them so the load reports them.
func wildcardKey(oid string) (string, bool) {
	prefix, hasStar := strings.CutSuffix(oid, "*")
	if !hasStar || strings.Contains(prefix, "*") {
		return "", false
	}
	prefix = strings.TrimSuffix(prefix, ".")
	if prefix == "" {
		return "", false
	}
	return prefix + ".*", true
}

// unindexableSysObjectID reports a pattern the matcher cannot turn into either
// an exact OID or a wildcard prefix. It carries a star, so no device can report
// it verbatim, and the star is not one this index reads, so the entry claims
// nothing. Every metric behind it is unreachable.
func unindexableSysObjectID(oid string) bool {
	if !strings.Contains(oid, "*") {
		return false
	}
	_, ok := wildcardKey(oid)
	return !ok
}

// normalizeOID strips a leading "." and "iso." prefix from an SNMP OID string.
// Devices return OIDs with a leading dot; profile patterns omit it.
func normalizeOID(raw string) string {
	oid := strings.TrimPrefix(strings.TrimSpace(raw), ".")
	oid = strings.TrimPrefix(oid, "iso.")
	return oid
}
