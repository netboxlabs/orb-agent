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

// matchRedirect is one compiled `matches` entry: a sysDescr pattern and the
// profile it redirects to.
type matchRedirect struct {
	re   *regexp.Regexp
	file string
}

// Matcher matches a device sysObjectID (and optionally sysDescr) to a Profile.
type Matcher struct {
	exactIndex    map[string]*Profile          // normalized OID -> profile (exact matches)
	wildcardIndex []wildcardEntry              // sorted longest-prefix-first for wildcard matches
	profileByFile map[string]*Profile          // filename -> profile (for matches redirects)
	redirects     map[*Profile][]matchRedirect // profile -> compiled matches patterns, in evaluation order
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
func NewMatcher(profiles []*Profile, logger *slog.Logger) *Matcher {
	byBase := make(map[string]keyClaims)
	byExact := make(map[string]keyClaims)
	byWildcard := make(map[string]keyClaims)

	for _, p := range profiles {
		byBase[p.FileName] = append(byBase[p.FileName], p)
		for _, raw := range p.SysObjectID {
			oid := normalizeOID(raw)
			if strings.HasSuffix(oid, ".*") {
				byWildcard[oid] = append(byWildcard[oid], p)
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
		if len(p.Matches) == 0 {
			continue
		}
		// Sort patterns for deterministic evaluation order.
		var compiled []matchRedirect
		for _, pattern := range slices.Sorted(maps.Keys(p.Matches)) {
			re, err := regexp.Compile("(?i)" + pattern)
			if err != nil {
				if logger != nil {
					logger.Warn("SNMP profile matches pattern is invalid, redirect disabled",
						"profile", p.RelPath, "pattern", pattern, "error", err)
				}
				continue
			}
			compiled = append(compiled, matchRedirect{re: re, file: p.Matches[pattern]})
		}
		if len(compiled) > 0 {
			m.redirects[p] = compiled
		}
	}

	return m
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
// Use MatchWithDescr when sysDescr is also available to support matches-redirect profiles.
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
// If the OID-matched profile has a matches section, the sysDescr is tested against each
// pattern (case-insensitive, compiled once in NewMatcher) and the first matching
// pattern's profile is returned instead. This mirrors how ktranslate handles devices
// that share a sysOID but differ by description.
func (m *Matcher) MatchWithDescr(deviceSysOID, sysDescr string) (*Profile, bool) {
	profile, ok := m.Match(deviceSysOID)
	if !ok {
		return nil, false
	}
	redirects, hasRedirects := m.redirects[profile]
	if !hasRedirects || sysDescr == "" {
		return profile, true
	}

	for _, r := range redirects {
		if !r.re.MatchString(sysDescr) {
			continue
		}
		if redirectProfile, found := m.profileByFile[r.file]; found {
			return redirectProfile, true
		}
	}

	// No redirect matched; use original profile.
	return profile, true
}

// ProfileCount returns the total number of indexed OID entries (exact + wildcard).
func (m *Matcher) ProfileCount() int {
	return len(m.exactIndex) + len(m.wildcardIndex)
}

// normalizeOID strips a leading "." and "iso." prefix from an SNMP OID string.
// Devices return OIDs with a leading dot; profile patterns omit it.
func normalizeOID(raw string) string {
	oid := strings.TrimPrefix(strings.TrimSpace(raw), ".")
	oid = strings.TrimPrefix(oid, "iso.")
	return oid
}
