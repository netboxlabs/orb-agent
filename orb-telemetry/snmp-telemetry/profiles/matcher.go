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

// Matcher matches a device sysObjectID (and optionally sysDescr) to a Profile.
type Matcher struct {
	exactIndex    map[string]*Profile // normalized OID -> profile (exact matches)
	wildcardIndex []wildcardEntry     // sorted longest-prefix-first for wildcard matches
	profileByFile map[string]*Profile // filename -> profile (for matches redirects)
}

// keyClaims holds every profile claiming one index key, in the order the
// profiles were indexed.
type keyClaims []*Profile

// kept is the profile that serves the key.
func (c keyClaims) kept() *Profile {
	return c.pick(func(*Profile) bool { return true })
}

// bundled is the profile that would serve the key if the override directory
// held nothing at a path the bundled set lacks. A file that replaces a bundled
// profile at that profile's own path counts here: it stands in for the bundled
// file rather than competing with it.
func (c keyClaims) bundled() *Profile {
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

	reportShadowed(byBase, logger, "basename")
	reportShadowed(byExact, logger, "sysobjectid")
	reportShadowed(byWildcard, logger, "sysobjectid")

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
	return m
}

// reportShadowed warns about keys a profile added under the override directory
// took from the profile that would otherwise have served them, which is the
// operator's to fix. Everything else is logged at debug level: the bundled set
// itself ships nine files named traps.yml, and comparing origins pairwise
// warned once per losing sibling, so correctly overriding one of them produced
// eight warnings naming vendors the operator never touched.
func reportShadowed(claims map[string]keyClaims, logger *slog.Logger, kind string) {
	if logger == nil {
		return
	}
	for _, key := range slices.Sorted(maps.Keys(claims)) {
		c := claims[key]
		if len(c) < 2 {
			continue
		}
		kept, bundled := c.kept(), c.bundled()
		if bundled != nil && bundled != kept {
			logger.Warn("SNMP profile shadows the one that would have served this key",
				kind, key, "using", kept.RelPath, "instead_of", bundled.RelPath)
			continue
		}
		ignoring := make([]string, 0, len(c)-1)
		for _, p := range c {
			if p != kept {
				ignoring = append(ignoring, p.RelPath)
			}
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
// pattern (case-insensitive) and the first matching pattern's profile is returned instead.
// This mirrors how ktranslate handles devices that share a sysOID but differ by description.
func (m *Matcher) MatchWithDescr(deviceSysOID, sysDescr string) (*Profile, bool) {
	profile, ok := m.Match(deviceSysOID)
	if !ok {
		return nil, false
	}
	if len(profile.Matches) == 0 || sysDescr == "" {
		return profile, true
	}

	// Sort patterns for deterministic evaluation order.
	patterns := slices.Sorted(maps.Keys(profile.Matches))

	lowerDescr := strings.ToLower(sysDescr)
	for _, pattern := range patterns {
		redirectFile := profile.Matches[pattern]
		matched, err := regexp.MatchString(pattern, lowerDescr)
		if err != nil || !matched {
			continue
		}
		if redirectProfile, found := m.profileByFile[redirectFile]; found {
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
