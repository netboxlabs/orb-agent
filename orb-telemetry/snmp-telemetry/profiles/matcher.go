package profiles

import (
	"regexp"
	"sort"
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

// NewMatcher builds a Matcher from a list of fully-resolved profiles.
// Profiles without any sysobjectid entries are ignored (they are base/inherited profiles).
func NewMatcher(profiles []*Profile) *Matcher {
	m := &Matcher{
		exactIndex:    make(map[string]*Profile),
		profileByFile: make(map[string]*Profile),
	}
	for _, p := range profiles {
		m.profileByFile[p.FileName] = p
		for _, raw := range p.SysObjectID {
			oid := normalizeOID(raw)
			if strings.HasSuffix(oid, ".*") {
				prefix := strings.TrimSuffix(oid, "*")
				m.wildcardIndex = append(m.wildcardIndex, wildcardEntry{prefix: prefix, profile: p})
			} else {
				m.exactIndex[oid] = p
			}
		}
	}
	// Sort wildcard entries by descending prefix length so the most specific match wins.
	sort.Slice(m.wildcardIndex, func(i, j int) bool {
		return len(m.wildcardIndex[i].prefix) > len(m.wildcardIndex[j].prefix)
	})
	return m
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
	patterns := make([]string, 0, len(profile.Matches))
	for p := range profile.Matches {
		patterns = append(patterns, p)
	}
	sort.Strings(patterns)

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
