package profiles

import (
	"embed"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed all:gnmi-profiles
var embeddedProfiles embed.FS

// Match holds the criteria that select a profile for a target. Only Vendor is
// auto-detected today (from Capabilities). Model/OS matching would require a
// /system/state read during selection (deferred); leaving those fields out keeps
// the matcher honest — a criterion we never populate would silently never fire.
//
// Vendor may be a single substring (e.g. "Arista") or a comma-separated list of
// aliases matched ANY-of (e.g. "nvidia,cumulus,mellanox"). Aliases let one
// overlay cover a vendor that reports different Organization strings across
// releases; a single-value Vendor behaves exactly as a one-element alias list.
type Match struct {
	Vendor string `yaml:"vendor,omitempty"`
}

// vendorAliases splits a (possibly comma-separated) Match.Vendor into its
// trimmed, lowercased, non-empty aliases. A single-value field yields a
// one-element slice, so existing single-token overlays are unaffected.
func (m Match) vendorAliases() []string {
	var out []string
	for _, a := range strings.Split(m.Vendor, ",") {
		a = strings.ToLower(strings.TrimSpace(a))
		if a != "" {
			out = append(out, a)
		}
	}
	return out
}

// Metric is one leaf under a subscription exported as gnmi.<Name>. Leaf is
// relative to the subscription path; "." means the subscription path itself.
type Metric struct {
	Leaf string           `yaml:"leaf"`
	Name string           `yaml:"name"`
	Type string           `yaml:"type"`
	Unit string           `yaml:"unit,omitempty"`
	Enum map[string]int64 `yaml:"enum,omitempty"`
	Bool bool             `yaml:"bool,omitempty"`
}

// Subscription is one subtree or leaf: its mode, origin override, the path
// keys promoted to attributes, and the metrics its leaves yield.
type Subscription struct {
	Path       string            `yaml:"path"`
	Mode       string            `yaml:"mode"`
	Origin     *string           `yaml:"origin,omitempty"`
	Attributes map[string]string `yaml:"attributes,omitempty"`
	Metrics    []Metric          `yaml:"metrics"`
}

// Profile is a named set of subscriptions; an overlay extends a parent. An
// overlay with no subscriptions of its own is a placeholder that inherits
// everything.
type Profile struct {
	Name          string         `yaml:"-"`
	Extends       string         `yaml:"extends,omitempty"`
	Match         Match          `yaml:"match"`
	Subscriptions []Subscription `yaml:"subscriptions"`
}

var metricName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// Validate checks the schema rules: a path and metrics per subscription, a
// stream mode, metric types, unique lower-case names, enum and bool only on
// gauges, and a "." leaf alone in its subscription.
func (p *Profile) Validate() error {
	seen := map[string]bool{}
	for i, s := range p.Subscriptions {
		if s.Path == "" {
			return fmt.Errorf("profile %s: subscription %d: path is required", p.Name, i+1)
		}
		if s.Mode != "sample" && s.Mode != "on_change" {
			return fmt.Errorf("profile %s: subscription %q: mode %q is not sample or on_change", p.Name, s.Path, s.Mode)
		}
		if len(s.Metrics) == 0 {
			return fmt.Errorf("profile %s: subscription %q: no metrics", p.Name, s.Path)
		}
		for _, m := range s.Metrics {
			if m.Leaf == "" {
				return fmt.Errorf("profile %s: subscription %q: a metric has no leaf", p.Name, s.Path)
			}
			if m.Leaf == "." && len(s.Metrics) != 1 {
				return fmt.Errorf("profile %s: subscription %q: a \".\" leaf must be the only metric", p.Name, s.Path)
			}
			if !metricName.MatchString(m.Name) {
				return fmt.Errorf("profile %s: metric %q: name must be lower-case letters, digits and underscores", p.Name, m.Name)
			}
			if m.Type != "counter" && m.Type != "gauge" {
				return fmt.Errorf("profile %s: metric %q: type %q is not counter or gauge", p.Name, m.Name, m.Type)
			}
			if m.Type == "counter" && (len(m.Enum) > 0 || m.Bool) {
				return fmt.Errorf("profile %s: metric %q: enum and bool apply to gauges only", p.Name, m.Name)
			}
			if seen[m.Name] {
				return fmt.Errorf("profile %s: metric %q is declared twice", p.Name, m.Name)
			}
			seen[m.Name] = true
		}
	}
	return nil
}

// MatchInput is what we learn about a target from Capabilities.
type MatchInput struct {
	Vendor string
}

// Store holds all loaded, fully-resolved profiles.
type Store struct {
	profiles map[string]*Profile
}

// Get returns a profile by name.
func (s *Store) Get(name string) (*Profile, bool) {
	p, ok := s.profiles[name]
	return p, ok
}

// Names lists the loaded profiles, sorted.
func (s *Store) Names() []string {
	names := make([]string, 0, len(s.profiles))
	for n := range s.profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Match returns the matching profile, or _base when nothing matches. A profile
// matches when ANY of its vendor aliases is a substring of the input vendor.
// When more than one profile matches, the MOST SPECIFIC one wins, where
// specificity is the length of the LONGEST alias that actually matched — so a
// "Arista 7050" alias beats a generic "Arista", and within an alias list the
// longest matched token sets the score. Ties are broken deterministically by
// sorted profile name. (A single-value Match.Vendor scores by its own length,
// preserving the prior behavior exactly.)
func (s *Store) Match(in MatchInput) *Profile {
	names := make([]string, 0, len(s.profiles))
	for name := range s.profiles {
		if name != "_base" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	vendor := strings.ToLower(in.Vendor)
	var best *Profile
	bestLen := 0
	for _, name := range names {
		p := s.profiles[name]
		// Longest alias of this profile that is a substring of the input vendor.
		matchedLen := 0
		for _, alias := range p.Match.vendorAliases() {
			if strings.Contains(vendor, alias) && len(alias) > matchedLen {
				matchedLen = len(alias)
			}
		}
		if matchedLen == 0 {
			continue // no alias matched (or profile has no criteria)
		}
		if matchedLen > bestLen {
			best, bestLen = p, matchedLen
		}
	}
	if best != nil {
		return best
	}
	return s.profiles["_base"]
}

// LoadProfiles loads the bundled profiles, overlays any in overrideDir,
// resolves extends and validates the result; unreadable or invalid overrides
// are skipped and logged, and logger may be nil.
func LoadProfiles(overrideDir string, logger *slog.Logger) (*Store, error) {
	raw := map[string]*Profile{}

	entries, err := embeddedProfiles.ReadDir("gnmi-profiles")
	if err != nil {
		return nil, fmt.Errorf("read embedded profiles: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		b, err := embeddedProfiles.ReadFile("gnmi-profiles/" + e.Name())
		if err != nil {
			return nil, err
		}
		if err := addProfile(raw, e.Name(), b); err != nil {
			return nil, err
		}
	}

	// Snapshot the bundled profiles by name so a bad override that reuses a
	// bundled filename can fall back to the built-in (below) instead of deleting
	// it when its inheritance fails to resolve.
	bundled := make(map[string]*Profile, len(raw))
	for name, p := range raw {
		bundled[name] = p
	}

	if overrideDir != "" {
		dirEntries, err := os.ReadDir(overrideDir)
		if err != nil {
			if logger != nil {
				logger.Warn("could not read profiles_dir; using bundled profiles only",
					"dir", overrideDir, "error", err)
			}
		} else {
			for _, e := range dirEntries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
					continue
				}
				path := filepath.Join(overrideDir, e.Name())
				b, err := os.ReadFile(path)
				if err != nil {
					if logger != nil {
						logger.Warn("skipping unreadable gNMI profile override", "file", path, "error", err)
					}
					continue
				}
				if err := addProfile(raw, e.Name(), b); err != nil {
					if logger != nil {
						logger.Warn("skipping invalid gNMI profile override", "file", path, "error", err)
					}
					continue
				}
				// A same-name override that doesn't restate `match` (the common
				// "tweak only the leaf paths" case, typically `extends: _base`)
				// inherits the bundled profile's vendor criteria — otherwise it
				// becomes unmatchable and auto-detection silently falls back to
				// _base, ignoring the override.
				name := strings.TrimSuffix(e.Name(), ".yaml")
				if base, ok := bundled[name]; ok && raw[name].Match.Vendor == "" {
					raw[name].Match = base.Match
				}
			}
		}
	}

	// First pass: restore the bundled version of any profile whose (override) entry
	// fails to resolve. Doing this BEFORE the resolve pass below — rather than
	// inline per-name — means a bad override of a shared PARENT (e.g. a broken
	// _base override) is restored regardless of the randomized map iteration order,
	// so children that `extend` it resolve against the good bundled parent instead
	// of being skipped. A typo in e.g. /profiles/arista_eos.yaml likewise falls
	// back to the bundled Arista.
	for name := range raw {
		if _, err := resolve(name, raw, map[string]bool{}); err != nil {
			if b, ok := bundled[name]; ok && raw[name] != b {
				raw[name] = b
				if logger != nil {
					logger.Warn("gNMI profile override failed to resolve; falling back to bundled profile",
						"profile", name, "error", err)
				}
			}
		}
	}

	resolveAll := func() map[string]*Profile {
		out := map[string]*Profile{}
		for name := range raw {
			p, err := resolve(name, raw, map[string]bool{})
			if err != nil {
				// A semantically-bad profile (unresolved `extends` or an inheritance
				// cycle) must not crash startup, skip and log it, like a bad parse.
				// _base has no `extends` so it always resolves; the matcher still has
				// its fallback. (Bundled profiles are expected to resolve; a failure
				// there is a build bug, surfaced via this same log.)
				if logger != nil {
					logger.Warn("skipping gNMI profile with unresolved inheritance", "profile", name, "error", err)
				}
				continue
			}
			out[name] = p
		}
		return out
	}
	resolved := resolveAll()

	// Validation mirrors the restore above: a pass over the resolved profiles
	// only restores an invalid override to its bundled version or drops one that
	// has none, never erroring, and the passes repeat while anything changed.
	// Leaving an entry that already IS its bundled one for the next pass is what
	// makes a bad shared parent survivable: `resolved` was built before any
	// restore, so every child of an invalid _base override is invalid in the
	// first pass too and erroring there would turn one bad override file into a
	// fatal startup, whatever the map order. Repeating also covers an override
	// that was valid against an overridden parent and invalid against the
	// restored one; it is skipped like any other bad override. The loop is
	// bounded by the number of names, because each change replaces an override
	// with its bundled entry or drops it.
	var invalid error
	for {
		changed := false
		invalid = nil
		for name, p := range resolved {
			err := p.Validate()
			if err == nil {
				continue
			}
			if invalid == nil {
				invalid = err
			}
			b, ok := bundled[name]
			switch {
			case ok && raw[name] != b:
				raw[name] = b
				changed = true
				if logger != nil {
					logger.Warn("invalid gNMI profile override; falling back to bundled profile",
						"profile", name, "error", err)
				}
			case !ok:
				delete(raw, name)
				changed = true
				if logger != nil {
					logger.Warn("skipping invalid gNMI profile", "profile", name, "error", err)
				}
			}
		}
		if !changed {
			break
		}
		// Re-resolve every name still in raw into a fresh map: a stale entry must
		// not outlive a delete, and copying bundled[name] in place of the resolved
		// profile would drop what a bundled overlay inherits from its parent.
		resolved = resolveAll()
	}
	// Every entry still standing is the bundled one, so a validation error here
	// is a build bug rather than a bad override.
	if invalid != nil {
		return nil, invalid
	}
	if _, ok := resolved["_base"]; !ok {
		return nil, fmt.Errorf("bundled _base profile failed to load")
	}
	return &Store{profiles: resolved}, nil
}

func addProfile(into map[string]*Profile, filename string, b []byte) error {
	var p Profile
	if err := yaml.Unmarshal(b, &p); err != nil {
		return fmt.Errorf("parse profile %s: %w", filename, err)
	}
	p.Name = strings.TrimSuffix(filename, ".yaml")
	into[p.Name] = &p
	return nil
}

// resolve produces a profile with its parent's values filled in where the
// child left them empty. Child keys win on conflict.
func resolve(name string, raw map[string]*Profile, seen map[string]bool) (*Profile, error) {
	if seen[name] {
		return nil, fmt.Errorf("profile inheritance cycle at %q", name)
	}
	seen[name] = true
	p, ok := raw[name]
	if !ok {
		return nil, fmt.Errorf("profile %q not found", name)
	}
	if p.Extends == "" {
		return p, nil
	}
	parent, err := resolve(p.Extends, raw, seen)
	if err != nil {
		return nil, err
	}
	return merge(parent, p), nil
}

// merge overlays child on parent: match from the child when set,
// subscriptions replaced by path and otherwise appended in the child's order.
func merge(parent, child *Profile) *Profile {
	out := &Profile{Name: child.Name, Extends: child.Extends, Match: parent.Match}
	if child.Match.Vendor != "" {
		out.Match = child.Match
	}
	index := map[string]int{}
	for _, s := range parent.Subscriptions {
		index[s.Path] = len(out.Subscriptions)
		out.Subscriptions = append(out.Subscriptions, s)
	}
	for _, s := range child.Subscriptions {
		if i, ok := index[s.Path]; ok {
			out.Subscriptions[i] = s
			continue
		}
		index[s.Path] = len(out.Subscriptions)
		out.Subscriptions = append(out.Subscriptions, s)
	}
	return out
}
