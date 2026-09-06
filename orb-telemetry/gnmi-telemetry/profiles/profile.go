package profiles

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"

	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"
	gpath "github.com/openconfig/gnmic/pkg/api/path"
	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/metrics"
)

//go:embed all:gnmi-profiles
var embeddedProfiles embed.FS

// Match holds the criteria that select a profile for a target. Capabilities
// auto-detects both of them: the hardware vendor, and the network OS when the
// target names one. Model matching would require a /system/state read during
// selection (deferred); leaving that field out keeps the matcher honest, since
// a criterion we never populate would silently never fire.
//
// Vendor may be a single substring (e.g. "Arista") or a comma-separated list of
// aliases matched ANY-of (e.g. "nvidia,cumulus,mellanox"). Aliases let one
// overlay cover a vendor that reports different Organization strings across
// releases; a single-value Vendor behaves exactly as a one-element alias list.
//
// NOS is one canonical network-OS name (e.g. "sonic"), compared whole and
// case-insensitively rather than as a substring. A NOS is not a manufacturer,
// so Capabilities never derives a vendor from one; matching on NOS is what
// makes such an overlay reachable without pinning it per target.
type Match struct {
	Vendor string `yaml:"vendor,omitempty"`
	NOS    string `yaml:"nos,omitempty"`
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

// maxMetricNameLen is the longest name the exporter can stand an instrument
// for. The metric SDK refuses an instrument name longer than 255 characters
// ("longer than 255 characters", sdk/metric.validateInstrumentName), and the
// exporter creates every instrument under the name prefixed with "gnmi.", so
// the profile's own name has that much less room. Nothing downstream reports
// the refusal: instrument creation only logs, while the series goes on holding
// a slot of the collector's budget for a name that is never exported.
const maxMetricNameLen = 255 - len("gnmi.")

// reservedAttributes are the attribute names the collector sets on every
// series it writes. A profile that promotes a path key under one of them
// would have the collector's value and its own on the same series.
var reservedAttributes = map[string]bool{"device_ip": true, "policy": true, "netbox_id": true}

// reservedMetrics are the metric names the backend writes for its own health,
// taken from the package that owns those instruments so the two cannot drift.
// The exporter registers one instrument per metric name, so a profile metric
// named after one of them would stand a second instrument, of whatever kind
// the profile declared, beside the backend's own.
var reservedMetrics = func() map[string]bool {
	out := map[string]bool{}
	for _, n := range metrics.HealthNames() {
		out[n] = true
	}
	return out
}()

// nonEmptySegments splits a relative leaf on "/" and drops the empty pieces a
// leading, trailing or doubled slash leaves behind.
func nonEmptySegments(leaf string) []string {
	var out []string
	for _, seg := range strings.Split(leaf, "/") {
		if seg != "" {
			out = append(out, seg)
		}
	}
	return out
}

// canonicalPath renders a parsed path back to one spelling: the element names
// joined by "/", each with its own keys appended in name order. Two spellings
// the request parser reads alike, a trailing "/" for instance, render alike, so
// it is what a subscription is deduplicated on. A subscription's origin is a
// field of its own rather than part of its path, so the elements are the whole
// of the path here.
func canonicalPath(p *gnmiproto.Path) string {
	var b strings.Builder
	for _, e := range p.GetElem() {
		b.WriteString("/")
		b.WriteString(e.GetName())
		keys := e.GetKey()
		names := make([]string, 0, len(keys))
		for k := range keys {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			b.WriteString("[" + k + "=" + keys[k] + "]")
		}
	}
	return b.String()
}

// Validate checks the schema rules: at least one subscription, a path and
// metrics per subscription, a path the request parser accepts and no two
// subscriptions on one path, a stream mode, metric types, unique lower-case
// names that no health metric of the backend already owns and are short enough
// that the exporter's prefixed form stands as an instrument, enum and bool only
// on gauges, a "." leaf alone in its subscription, a leaf carrying neither a
// key predicate nor a module prefix and mapped by one metric of its
// subscription, an attribute that names a key its own path carries on exactly
// one element and does not shadow the collector's own names, and an attribute
// promoting every key the path wildcards.
//
// It reads a RESOLVED profile, which is what the loader validates: a
// placeholder overlay states no subscriptions of its own but carries its
// parent's by the time it gets here.
func (p *Profile) Validate() error {
	// A profile that resolves to no subscriptions asks its targets for nothing
	// and exports nothing, while its match criteria still win it targets the
	// profile below it would have served.
	if len(p.Subscriptions) == 0 {
		return fmt.Errorf("profile %s has no subscriptions", p.Name)
	}
	seen := map[string]bool{}
	paths := map[string]bool{}
	for i, s := range p.Subscriptions {
		if s.Path == "" {
			return fmt.Errorf("profile %s: subscription %d: path is required", p.Name, i+1)
		}
		// The request builders parse every path with this parser, and one path
		// it rejects fails the whole subscribe or Get request rather than its
		// own entry. The matcher's parser is more forgiving (an unbalanced
		// bracket is just a key part to it), so a path only it accepts loads
		// here and then has every target on the profile walk the ladder to the
		// bottom exporting nothing. Parsing with the builders' own parser is
		// what keeps validation and the wire in agreement.
		gp, err := gpath.ParsePath(s.Path)
		if err != nil {
			return fmt.Errorf("profile %s: subscription %q: path does not parse: %v", p.Name, s.Path, err)
		}
		// merge keys a parent's subscriptions by path, so a path stated twice
		// in one file is the only way a duplicate reaches here, and it is a
		// mistake: both entries sit at the same depth, so matchUpdate's deepest
		// wins preference keeps whichever comes first and the other's metrics
		// are never written, while Get polling buckets metric names by path and
		// would merge the two. Keyed on what the path parses to rather than on
		// what the file wrote, so two spellings of one path, a trailing "/" for
		// instance, are the one subscription the device and the matcher both
		// see.
		// The matcher drops module prefixes from the paths a target sends, so a
		// qualified element here would never match and would also let one path
		// be declared twice under two spellings.
		for _, e := range gp.GetElem() {
			if strings.Contains(e.GetName(), ":") {
				return fmt.Errorf("profile %s: subscription %q: path elements are written without a module prefix", p.Name, s.Path)
			}
		}
		canon := canonicalPath(gp)
		if paths[canon] {
			return fmt.Errorf("profile %s: subscription %q is declared twice", p.Name, s.Path)
		}
		paths[canon] = true
		if s.Mode != "sample" && s.Mode != "on_change" {
			return fmt.Errorf("profile %s: subscription %q: mode %q is not sample or on_change", p.Name, s.Path, s.Mode)
		}
		if len(s.Metrics) == 0 {
			return fmt.Errorf("profile %s: subscription %q: no metrics", p.Name, s.Path)
		}
		// An attribute is filled from the keys the update path carries, so one
		// naming a key the subscription path does not have is dropped from
		// every series in silence, collapsing each element of the list onto
		// one series. Sorted, so a subscription with two bad attributes always
		// names the same one.
		keys := pathKeyCounts(s.Path)
		attrs := make([]string, 0, len(s.Attributes))
		for attr := range s.Attributes {
			attrs = append(attrs, attr)
		}
		sort.Strings(attrs)
		for _, attr := range attrs {
			if reservedAttributes[attr] {
				return fmt.Errorf("profile %s: subscription %q: attribute %s is set by the collector", p.Name, s.Path, attr)
			}
			switch key := s.Attributes[attr]; {
			case keys[key] == 0:
				return fmt.Errorf("profile %s: subscription %q: attribute %s names key %s, which the path does not carry",
					p.Name, s.Path, attr, key)
			case keys[key] > 1:
				// Two nested lists keyed alike, e.g. a network-instance and an
				// interface both keyed name. One name cannot fill two attributes
				// with different values, so both would carry the deeper list's
				// and every series of the outer list would collapse onto one.
				return fmt.Errorf("profile %s: subscription %q: attribute %s names key %s, which more than one element of the path carries; keys must be unique along the path",
					p.Name, s.Path, attr, key)
			}
		}
		// A wildcard key is what makes one subscription cover every element of
		// a list, and its value is the only thing that tells the elements
		// apart. With no attribute promoting it, every element writes the same
		// series and each one silently overwrites the last. A literal key names
		// a single element, so it needs nothing.
		promoted := make(map[string]bool, len(s.Attributes))
		for _, key := range s.Attributes {
			promoted[key] = true
		}
		for _, key := range wildcardKeys(s.Path) {
			if !promoted[key] {
				return fmt.Errorf("profile %s: subscription %q: wildcard key %s must be promoted by an attribute, or every element shares one series",
					p.Name, s.Path, key)
			}
		}
		// A leaf carries one value, and a match writes it to the first metric
		// mapping that leaf and stops, so a second metric on the same leaf is
		// never exported and the profile promises a series nothing writes.
		// Scoped to the subscription: the same leaf name under two paths is
		// two different leaves.
		leaves := make(map[string]bool, len(s.Metrics))
		for _, m := range s.Metrics {
			if m.Leaf == "" {
				return fmt.Errorf("profile %s: subscription %q: a metric has no leaf", p.Name, s.Path)
			}
			if m.Leaf == "." && len(s.Metrics) != 1 {
				return fmt.Errorf("profile %s: subscription %q: a \".\" leaf must be the only metric", p.Name, s.Path)
			}
			// A leaf is matched against the update path by element name
			// alone, so a predicate in it matches nothing and the metric is
			// never exported; dropping the predicate instead would have every
			// element of the list write one shared series. A keyed list belongs
			// in the subscription path, where an attribute promotes its key.
			if strings.Contains(m.Leaf, "[") {
				return fmt.Errorf("profile %s: subscription %q: metric %s: a leaf cannot carry a key predicate; put the keyed list in the subscription path and promote its key",
					p.Name, s.Path, m.Name)
			}
			// The matcher drops a module prefix from every element of an
			// incoming path, so it compares bare names and a leaf carrying one
			// matches nothing: the metric is never exported, and every update
			// under the subscription is counted as an unmatched path.
			if strings.Contains(m.Leaf, ":") {
				return fmt.Errorf("profile %s: subscription %q: metric %s: a leaf is written without a module prefix",
					p.Name, s.Path, m.Name)
			}
			// The request parser drops empty elements, so a leaf written with a
			// leading, trailing or doubled slash parses, but the matcher hands
			// back the canonical spelling and compares it against the leaf as
			// written, which never matches; the same slack would let two
			// spellings of one leaf pass the duplicate check.
			if m.Leaf != "." && m.Leaf != strings.Join(nonEmptySegments(m.Leaf), "/") {
				return fmt.Errorf("profile %s: subscription %q: metric %s: a leaf is written without a leading, trailing or repeated slash",
					p.Name, s.Path, m.Name)
			}
			// A metric's full path is its subscription path plus its leaf, and
			// that is the form the device's own update paths take. A leaf that
			// makes the join unparseable can never be a path an update carries,
			// so the metric names a series nothing ever writes.
			if m.Leaf != "." {
				if _, err := gpath.ParsePath(s.Path + "/" + m.Leaf); err != nil {
					return fmt.Errorf("profile %s: subscription %q: metric %s: path does not parse: %v",
						p.Name, s.Path, m.Name, err)
				}
			}
			if leaves[m.Leaf] {
				return fmt.Errorf("profile %s: subscription %q: leaf %s is mapped twice", p.Name, s.Path, m.Leaf)
			}
			leaves[m.Leaf] = true
			if !metricName.MatchString(m.Name) {
				return fmt.Errorf("profile %s: metric %q: name must be lower-case letters, digits and underscores", p.Name, m.Name)
			}
			if len(m.Name) > maxMetricNameLen {
				return fmt.Errorf("profile %s: subscription %q: metric %s: name longer than %d characters",
					p.Name, s.Path, m.Name, maxMetricNameLen)
			}
			if reservedMetrics[m.Name] {
				return fmt.Errorf("profile %s: subscription %q: metric name %s is reserved for the backend's health metrics",
					p.Name, s.Path, m.Name)
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

// MatchInput is what we learn about a target from Capabilities: the hardware
// vendor, and the network OS when one was detected. They are independent, and a
// target that reports a NOS commonly reports the OEM that built the hardware as
// its vendor, so both are passed and the NOS is the stronger signal.
type MatchInput struct {
	Vendor string
	NOS    string
	// Organizations are the organization strings the target reported, as it
	// wrote them. Capabilities derives Vendor only from the organizations it
	// knows, so a target of any other vendor arrives here with an empty Vendor
	// and these are what a profile written for it is matched on.
	Organizations []string
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

// Match returns the matching profile, or _base when nothing matches. A detected
// NOS is tried first: a profile whose match.nos equals it, whole and
// case-insensitively, wins outright, because a NOS overlay describes the very
// software serving the paths, while the vendor under it is only the OEM that
// built the box. Failing that, a profile matches when ANY of its vendor aliases
// is a substring of the input vendor. When more than one profile matches by
// vendor, the MOST SPECIFIC one wins, where specificity is the length of the
// LONGEST alias that actually matched, so an "Arista 7050" alias beats a
// generic "Arista", and within an alias list the longest matched token sets the
// score. Ties are broken deterministically by sorted profile name. (A
// single-value Match.Vendor scores by its own length, preserving the prior
// behavior exactly.) Failing that, the organizations the target reported are
// tried, so a vendor the capability mapping does not know still reaches the
// overlay written for it; the first profile in sorted name order wins there.
// _base is the fallback when no pass matched.
func (s *Store) Match(in MatchInput) *Profile {
	names := make([]string, 0, len(s.profiles))
	for name := range s.profiles {
		if name != "_base" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if nos := strings.ToLower(strings.TrimSpace(in.NOS)); nos != "" {
		for _, name := range names {
			p := s.profiles[name]
			if strings.ToLower(strings.TrimSpace(p.Match.NOS)) == nos {
				return p
			}
		}
	}
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
	// Capabilities derives a vendor only from the organizations it maps, so a
	// device of any other vendor reaches here with nothing but the organization
	// it reported, and an overlay carrying that vendor would never be selected:
	// every such target streamed _base however plainly the device named itself.
	// An alias is matched as a whole token of an organization rather than as a
	// substring of one, because an organization is written for people ("Acme
	// Networks, Inc.") and a substring of such a string says much less than a
	// word of it. A multi-word alias is a token of nothing and is carried by
	// the vendor pass above alone.
	for _, name := range names {
		p := s.profiles[name]
		for _, alias := range p.Match.vendorAliases() {
			for _, org := range in.Organizations {
				if hasToken(org, alias) {
					return p
				}
			}
		}
	}
	return s.profiles["_base"]
}

// hasToken reports whether org carries token as a whole-word phrase, compared
// case-insensitively: both sides are split on everything that is neither a
// letter nor a digit, so the punctuation a device writes around its name is not
// part of what is matched, and a multi-word alias such as "acme networks" must
// appear as those words in that order.
func hasToken(org, token string) bool {
	want := words(token)
	if len(want) == 0 {
		return false
	}
	have := words(org)
	for i := 0; i+len(want) <= len(have); i++ {
		match := true
		for j := range want {
			if !strings.EqualFold(have[i+j], want[j]) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// words splits a string on everything that is neither a letter nor a digit.
func words(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

// metricSchema is how one exported metric name reaches the SDK: the kind of
// instrument it becomes and the unit it carries.
type metricSchema struct {
	typ  string
	unit string
}

// schemaConflicts reports, for each profile that disagrees, the first metric
// name it defines with a kind or unit another profile already claimed. The SDK
// holds one instrument per metric name however many profiles feed it, so a
// store where if_in_octets is a byte counter in one profile and a packet gauge
// in another exports that name as two conflicting streams; Validate cannot see
// it, because its uniqueness check is within a single profile.
//
// Which profile keeps a name is fixed rather than left to the map order the
// profiles resolved in: the definitions of the profiles still standing as
// bundled are registered first, then the overrides, each group by sorted name.
// A bundled definition therefore always outranks an override that disagrees
// with it, and between two overrides the sorted-first one wins.
func schemaConflicts(resolved map[string]*Profile, isOverride func(name string) bool) map[string]error {
	var bundledNames, overrideNames []string
	for name := range resolved {
		if isOverride(name) {
			overrideNames = append(overrideNames, name)
		} else {
			bundledNames = append(bundledNames, name)
		}
	}
	sort.Strings(bundledNames)
	sort.Strings(overrideNames)

	held := map[string]metricSchema{}
	owner := map[string]string{}
	out := map[string]error{}
	for _, name := range append(bundledNames, overrideNames...) {
		// A profile is judged as a whole before it registers anything: one
		// that loses on a name is dropped by the loader, so letting it claim
		// its other names first would make a later profile lose to a
		// definition that is about to disappear.
		for _, sub := range resolved[name].Subscriptions {
			for _, m := range sub.Metrics {
				want, seen := held[m.Name]
				if seen && (want.typ != m.Type || want.unit != m.Unit) && out[name] == nil {
					out[name] = fmt.Errorf("profile %s: metric %q is %s in unit %q here and %s in unit %q in profile %s; one metric name has one type and unit across every profile",
						name, m.Name, m.Type, m.Unit, want.typ, want.unit, owner[m.Name])
				}
			}
		}
		if out[name] != nil {
			continue
		}
		for _, sub := range resolved[name].Subscriptions {
			for _, m := range sub.Metrics {
				if _, seen := held[m.Name]; !seen {
					held[m.Name] = metricSchema{typ: m.Type, unit: m.Unit}
					owner[m.Name] = name
				}
			}
		}
	}
	return out
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
				// inherits the bundled profile's criteria, otherwise it becomes
				// unmatchable and auto-detection silently falls back to _base,
				// ignoring the override. An override that states either
				// criterion states them both.
				name := strings.TrimSuffix(e.Name(), ".yaml")
				if base, ok := bundled[name]; ok && raw[name].Match.Vendor == "" && raw[name].Match.NOS == "" {
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
	// restored one; it is skipped like any other bad override.
	//
	// A profile that disagrees with another about a metric name's type or unit
	// takes the same path, but never in the same pass as a profile that failed
	// on its own: an invalid profile contributes nothing to the store, so the
	// names it claims are not names anything else has to agree with, and judging
	// the conflicts against them would mark the valid profile defining one of
	// those names too and drop both at once, which no later pass can undo.
	// Conflicts are therefore computed only among the profiles that validated,
	// and only once the validation step has left a pass with nothing to change.
	// They are recomputed each pass, because the profile a name disagreed with
	// may itself have been restored or dropped since.
	//
	// The loop is bounded by the number of names, because each change replaces
	// an override with its bundled entry or drops it, and neither can happen to
	// one name twice.
	var invalid error
	// fallBack restores an override to the bundled profile it displaced, or
	// drops one that displaced nothing, and reports whether it changed the set.
	// An entry already standing as its bundled self has nothing to fall back to;
	// it is left alone, and `invalid` carries it out below as a build bug.
	fallBack := func(name string, err error) bool {
		if invalid == nil {
			invalid = err
		}
		b, ok := bundled[name]
		switch {
		case ok && raw[name] != b:
			raw[name] = b
			if logger != nil {
				logger.Warn("invalid gNMI profile override; falling back to bundled profile",
					"profile", name, "error", err)
			}
			return true
		case !ok:
			delete(raw, name)
			if logger != nil {
				logger.Warn("skipping invalid gNMI profile", "profile", name, "error", err)
			}
			return true
		}
		return false
	}
	for {
		changed := false
		invalid = nil
		valid := make(map[string]*Profile, len(resolved))
		for name, p := range resolved {
			if err := p.Validate(); err != nil {
				changed = fallBack(name, err) || changed
				continue
			}
			valid[name] = p
		}
		if !changed {
			// A name the process exports has one kind and unit, which no single
			// profile can settle: the conflict belongs to whichever profile
			// disagrees with the definition already registered.
			conflicts := schemaConflicts(valid, func(name string) bool {
				b, ok := bundled[name]
				return !ok || raw[name] != b
			})
			for name, err := range conflicts {
				changed = fallBack(name, err) || changed
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

// addProfile decodes one profile file. Decoding refuses a field the schema
// does not name: yaml.Unmarshal drops one silently, so a misspelled "unit"
// exported the metric without its unit, and an overlay whose "subscriptions"
// key was misspelled loaded as a bare copy of its parent, both looking like a
// profile that loaded as written.
func addProfile(into map[string]*Profile, filename string, b []byte) error {
	var p Profile
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("parse profile %s: %w", filename, err)
	}
	// One document per file: a second one after "---" would otherwise load
	// as nothing, its settings silently without effect.
	if err := dec.Decode(new(struct{})); !errors.Is(err, io.EOF) {
		return fmt.Errorf("parse profile %s: the file must hold one YAML document", filename)
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
	return merge(parent, p)
}

// merge overlays child on parent: match from the child when set,
// subscriptions replaced by path and otherwise appended in the child's order.
//
// Replacement is keyed on what a path parses to, as the duplicate check is,
// not on the text the file wrote. Keyed on the text, a child restating a
// parent's path in another spelling, a trailing "/" for one, was appended
// beside it, and validation then refused the whole profile as declaring the
// path twice.
//
// A child declaring one path twice is refused here: the second entry would
// take the replacement branch and overwrite the first, so the resolved profile
// carried the last entry alone and validation, which sees only the resolved
// profile, never saw the duplicate.
func merge(parent, child *Profile) (*Profile, error) {
	out := &Profile{Name: child.Name, Extends: child.Extends, Match: parent.Match}
	if child.Match.Vendor != "" || child.Match.NOS != "" {
		out.Match = child.Match
	}
	index := map[string]int{}
	for _, s := range parent.Subscriptions {
		index[mergeKey(s.Path)] = len(out.Subscriptions)
		out.Subscriptions = append(out.Subscriptions, s)
	}
	declared := map[string]bool{}
	for _, s := range child.Subscriptions {
		key := mergeKey(s.Path)
		if declared[key] {
			return nil, fmt.Errorf("profile %s: subscription %q is declared twice", child.Name, s.Path)
		}
		declared[key] = true
		if i, ok := index[key]; ok {
			out.Subscriptions[i] = s
			continue
		}
		index[key] = len(out.Subscriptions)
		out.Subscriptions = append(out.Subscriptions, s)
	}
	return out, nil
}

// mergeKey is the canonical spelling merge replaces subscriptions on. A path
// the request parser refuses keeps its text, for validation to report.
func mergeKey(path string) string {
	gp, err := gpath.ParsePath(path)
	if err != nil {
		return path
	}
	return canonicalPath(gp)
}
