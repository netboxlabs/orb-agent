package mapping

import (
	"embed"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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

// DeviceMap maps device-level fields to OpenConfig leaf paths.
type DeviceMap struct {
	Hostname  string `yaml:"hostname,omitempty"`
	OSVersion string `yaml:"os_version,omitempty"`
}

// ListMap maps a repeated OpenConfig list to entity keys. Key is the gNMI list
// key leaf used to build subscription wildcards (defaults to "name", correct for
// OpenConfig /interfaces/interface and /components/component); override it for a
// differently-keyed list.
type ListMap struct {
	ListPath string            `yaml:"list_path,omitempty"`
	Key      string            `yaml:"key,omitempty"`
	Keys     map[string]string `yaml:"keys,omitempty"`
}

// listKey returns the configured gNMI list key, defaulting to "name".
func (l ListMap) listKey() string {
	if l.Key != "" {
		return l.Key
	}
	return "name"
}

// Profile is one (possibly overlay) OpenConfig profile.
type Profile struct {
	Name       string    `yaml:"-"`
	Extends    string    `yaml:"extends,omitempty"`
	Match      Match     `yaml:"match"`
	Device     DeviceMap `yaml:"device"`
	Interfaces ListMap   `yaml:"interfaces"`
	Components ListMap   `yaml:"components"`
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

// LoadProfiles loads bundled profiles then overlays any in overrideDir, then
// resolves `extends` inheritance. Tests use this nil-logger form.
func LoadProfiles(overrideDir string) (*Store, error) {
	return LoadProfilesWithLogger(overrideDir, nil)
}

// LoadProfilesWithLogger is LoadProfiles with skip logging. Unreadable/invalid
// override files are skipped (so one bad file can't break startup), but each
// skip is logged (LOW) so a profile-rollout failure isn't mistaken for a silent
// _base fallback. logger may be nil.
func LoadProfilesWithLogger(overrideDir string, logger *slog.Logger) (*Store, error) {
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
				logger.Warn("could not read gNMI profiles_dir; using bundled profiles only",
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

	resolved := map[string]*Profile{}
	for name := range raw {
		p, err := resolve(name, raw, map[string]bool{})
		if err != nil {
			// A semantically-bad profile (unresolved `extends` or an inheritance
			// cycle) must not crash startup — skip and log it, like a bad parse.
			// _base has no `extends` so it always resolves; the matcher still has
			// its fallback. (Bundled profiles are expected to resolve; a failure
			// there is a build bug, surfaced via this same log.)
			if logger != nil {
				logger.Warn("skipping gNMI profile with unresolved inheritance", "profile", name, "error", err)
			}
			continue
		}
		resolved[name] = p
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

// merge overlays child onto a copy of parent.
func merge(parent, child *Profile) *Profile {
	out := *parent
	out.Name = child.Name
	out.Extends = child.Extends
	// Match is inherited from the parent unless the child restates it, mirroring
	// every other field below. Clobbering it unconditionally would drop the vendor
	// criteria of an "override only the differences" profile, so auto-detection
	// could no longer select it (it would fall back to _base).
	if child.Match.Vendor != "" {
		out.Match = child.Match
	}
	if child.Device.Hostname != "" {
		out.Device.Hostname = child.Device.Hostname
	}
	if child.Device.OSVersion != "" {
		out.Device.OSVersion = child.Device.OSVersion
	}
	out.Interfaces = mergeList(parent.Interfaces, child.Interfaces)
	out.Components = mergeList(parent.Components, child.Components)
	return &out
}

func mergeList(parent, child ListMap) ListMap {
	out := ListMap{ListPath: parent.ListPath, Key: parent.Key, Keys: map[string]string{}}
	for k, v := range parent.Keys {
		out.Keys[k] = v
	}
	if child.ListPath != "" {
		out.ListPath = child.ListPath
	}
	if child.Key != "" {
		out.Key = child.Key
	}
	for k, v := range child.Keys {
		out.Keys[k] = v
	}
	return out
}

// SubscribePaths returns the exact curated leaf paths to subscribe to (spec §6),
// using gNMI list wildcards so the target streams only inventory leaves — never
// volatile telemetry. e.g. /interfaces/interface[name=*]/state/admin-status.
func (p *Profile) SubscribePaths() []string {
	var out []string
	if p.Device.Hostname != "" {
		out = append(out, p.Device.Hostname)
	}
	if p.Device.OSVersion != "" {
		out = append(out, p.Device.OSVersion)
	}
	addList := func(l ListMap) {
		for k, leaf := range l.Keys {
			if k == "name" || leaf == "" || l.ListPath == "" {
				continue // the list key arrives within the path; no leaf to subscribe
			}
			out = append(out, l.ListPath+"["+l.listKey()+"=*]/"+leaf)
		}
	}
	addList(p.Interfaces)
	addList(p.Components)
	// The OpenConfig subinterface IP subtree is standardized across vendors, so it
	// is always subscribed (assumes the OpenConfig /subinterfaces/.../{ipv4,ipv6}
	// shape under the interface list). AllowsPath gates the same paths symmetrically.
	if p.Interfaces.ListPath != "" {
		base := p.Interfaces.ListPath + "[" + p.Interfaces.listKey() + "=*]/subinterfaces/subinterface[index=*]"
		out = append(out,
			base+"/ipv4/addresses/address[ip=*]/state/prefix-length",
			base+"/ipv6/addresses/address[ip=*]/state/prefix-length",
		)
	}
	// The OpenConfig switched-vlan subtree is standardized across vendors, so it
	// is always subscribed under both the ethernet and aggregation containers.
	// AllowsPath gates the same leaves symmetrically via parseSwitchedVlanPath.
	if p.Interfaces.ListPath != "" {
		base := p.Interfaces.ListPath + "[" + p.Interfaces.listKey() + "=*]"
		for _, container := range []string{"ethernet", "aggregation"} {
			for _, leaf := range []string{"interface-mode", "access-vlan", "native-vlan", "trunk-vlans"} {
				out = append(out, base+"/"+container+"/switched-vlan/state/"+leaf)
			}
		}
	}
	// The OpenConfig network-instance VLAN subtree is a standardized top-level path
	// (independent of the interface list), so it is always subscribed. AllowsPath
	// gates it symmetrically via parseNetworkInstanceVlanPath.
	out = append(out,
		"/network-instances/network-instance[name=*]/vlans/vlan[vlan-id=*]/state/name",
		"/network-instances/network-instance[name=*]/vlans/vlan[vlan-id=*]/state/status",
	)
	// The OpenConfig network-instance VRF state and membership leaves are
	// standardized top-level paths (independent of the interface list), so they
	// are always subscribed. AllowsPath gates them symmetrically via
	// parseNetworkInstanceStatePath and parseNetworkInstanceIfacePath.
	out = append(out,
		"/network-instances/network-instance[name=*]/state/type",
		"/network-instances/network-instance[name=*]/state/route-distinguisher",
		"/network-instances/network-instance[name=*]/interfaces/interface[id=*]/state/interface",
		"/network-instances/network-instance[name=*]/interfaces/interface[id=*]/state/subinterface",
	)
	sort.Strings(out)
	return out
}

// AllowsPath reports whether an inbound update path is one of the curated leaves.
func (p *Profile) AllowsPath(path string) bool {
	if path == p.Device.Hostname || (p.Device.OSVersion != "" && path == p.Device.OSVersion) {
		return true
	}
	if leaf, ok := leafUnderList(path, p.Interfaces.ListPath); ok && hasKeyLeaf(p.Interfaces, leaf) {
		return true
	}
	if leaf, ok := leafUnderList(path, p.Components.ListPath); ok && hasKeyLeaf(p.Components, leaf) {
		return true
	}
	if _, _, _, _, leaf, ok := parseIPAddressPath(path, p.Interfaces.ListPath); ok && leaf == "state/prefix-length" {
		return true
	}
	if _, _, ok := parseSwitchedVlanPath(path, p.Interfaces.ListPath); ok {
		return true
	}
	if _, _, ok := parseNetworkInstanceVlanPath(path); ok {
		return true
	}
	if _, _, ok := parseNetworkInstanceStatePath(path); ok {
		return true
	}
	if _, _, _, ok := parseNetworkInstanceIfacePath(path); ok {
		return true
	}
	return false
}

// networkInstanceList is the OpenConfig network-instance list root. Deletes
// under it (a removed VRF, or a removed VLAN/interface beneath it) must be
// honored so ON_CHANGE removals reconcile out of the model promptly, matching
// the network-instance subtrees AllowsPath already accepts for updates.
const networkInstanceList = "/network-instances/network-instance"

// AllowsDelete reports whether a delete path falls within the curated subtrees
// (the interfaces list, the components list, the network-instance list, or the
// device leaves / their ancestors). This bounds the blast radius of an
// unexpected delete so a target cannot wipe unrelated state; a legitimate
// list-entry or subtree delete inside a curated area is allowed (M-2).
// pathOverlaps is true when either path is a prefix of the other (covers both
// "delete a child" and "delete an ancestor").
func (p *Profile) AllowsDelete(path string) bool {
	if p.Interfaces.ListPath != "" && pathOverlaps(path, p.Interfaces.ListPath) {
		return true
	}
	if p.Components.ListPath != "" && pathOverlaps(path, p.Components.ListPath) {
		return true
	}
	if pathOverlaps(path, networkInstanceList) {
		return true
	}
	return pathOverlaps(path, p.Device.Hostname) || pathOverlaps(path, p.Device.OSVersion)
}

// pathOverlaps reports whether a and b are equal or one is an ANCESTOR of the
// other on a YANG path boundary. Boundary-awareness matters: a raw prefix test
// would treat /interfaces/interface-state as "within" /interfaces/interface;
// here the next character after the shorter path must be "/" or "[" (a list key).
func pathOverlaps(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return a == b || isAncestorPath(a, b) || isAncestorPath(b, a)
}

func isAncestorPath(anc, desc string) bool {
	if !strings.HasPrefix(desc, anc) {
		return false
	}
	rest := desc[len(anc):]
	return strings.HasPrefix(rest, "/") || strings.HasPrefix(rest, "[")
}

// leafUnderList returns the leaf path beneath a list entry, e.g.
// (/interfaces/interface[name=Eth1]/state/mtu, /interfaces/interface) -> ("state/mtu", true).
func leafUnderList(path, listPath string) (string, bool) {
	if listPath == "" {
		return "", false
	}
	prefix := listPath + "["
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	rest := path[len(prefix):]
	c := strings.Index(rest, "]")
	if c < 0 {
		return "", false
	}
	return strings.TrimPrefix(rest[c+1:], "/"), true
}

func hasKeyLeaf(l ListMap, leaf string) bool {
	for k, v := range l.Keys {
		if k == "name" {
			continue
		}
		if v == leaf {
			return true
		}
	}
	return false
}
