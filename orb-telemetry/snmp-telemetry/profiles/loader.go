package profiles

import (
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
)

//go:embed all:snmp-profiles
var embeddedProfiles embed.FS

// Loader reads ktranslate-format SNMP profile YAML files from a directory tree
// and resolves the `extends` inheritance chain.
type Loader struct {
	dir       string
	byFile    map[string]*Profile // relative-path -> raw (unresolved) profile
	byBase    map[string]string   // basename -> first relative-path seen (for extends resolution)
	resolved  map[string]*Profile // relative-path -> fully merged profile
	deduped   map[string]*Profile // relative-path -> merged profile with duplicate metric names resolved
	resolving map[string]bool     // cycle detection
	logger    *slog.Logger
}

func newEmptyLoader(dir string, logger *slog.Logger) *Loader {
	return &Loader{
		dir:       dir,
		byFile:    make(map[string]*Profile),
		byBase:    make(map[string]string),
		resolved:  make(map[string]*Profile),
		deduped:   make(map[string]*Profile),
		resolving: make(map[string]bool),
		logger:    logger,
	}
}

// NewLoader creates a Loader and reads all .yaml/.yml files from dir recursively.
// Prefer LoadProfiles, which includes the bundled set; this remains for callers
// that genuinely want a directory and nothing else, and for tests.
func NewLoader(dir string, logger *slog.Logger) (*Loader, error) {
	l := newEmptyLoader(dir, logger)
	if err := l.readDir(); err != nil {
		return nil, err
	}
	return l, nil
}

// LoadProfiles returns a Loader over the profiles bundled into the binary,
// overlaid by any found in overrideDir.
//
// The bundled set is the reason this exists: the agent image copies only the
// built binary, so a loader that reads solely from disk finds nothing there
// while every test that hands it a directory passes.
func LoadProfiles(overrideDir string, logger *slog.Logger) (*Loader, error) {
	l := newEmptyLoader("", logger)
	if err := l.readFS(embeddedProfiles, "snmp-profiles"); err != nil {
		return nil, fmt.Errorf("reading embedded profiles: %w", err)
	}
	if overrideDir != "" {
		bundled := make(map[string]bool, len(l.byFile))
		for rel := range l.byFile {
			bundled[rel] = true
		}
		l.dir = overrideDir
		if err := l.readDir(); err != nil {
			return nil, fmt.Errorf("reading override profiles from %s: %w", overrideDir, err)
		}
		l.reviewOverrides(bundled)
	}
	return l, nil
}

// reviewOverrides marks the override files that stand in for a bundled profile
// and warns about the ones that look like they were meant to.
//
// An override only replaces a bundled profile when its path under the override
// directory matches the bundled file's path exactly, so a file dropped at the
// override root loads as an extra profile and leaves the bundled one in place.
// Nothing else tells the operator that, and the two outcomes look identical
// from the collected metrics.
//
// The discriminator is the basename. A file carrying a bundled profile's
// basename from somewhere other than that profile's path was almost certainly
// meant to replace it. A basename the bundled set does not carry is a new
// profile, which is a supported use of the override directory and replaces
// nothing by design.
func (l *Loader) reviewOverrides(bundled map[string]bool) {
	for _, rel := range slices.Sorted(maps.Keys(l.byFile)) {
		p := l.byFile[rel]
		if p.Origin != OriginOverride {
			continue
		}
		if bundled[rel] {
			p.ReplacesBundled = true
			continue
		}
		want, ok := l.byBase[p.FileName]
		if !ok || !bundled[want] {
			continue
		}
		l.logger.Warn("SNMP profile override sits at the wrong path and replaces nothing",
			"file", config.SanitizeLogValue(rel), "override_dir", config.SanitizeLogValue(l.dir),
			"expected_path", config.SanitizeLogValue(want))
	}
}

// readFS loads every profile under root in fsys. An override read afterwards
// replaces an entry with the same relative path, which is what makes the
// override an overlay rather than a separate set.
func (l *Loader) readFS(fsys fs.FS, root string) error {
	return fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("reading profile %s: %w", path, err)
		}
		var p Profile
		if err := yaml.Unmarshal(data, &p); err != nil {
			l.logger.Warn("Skipping invalid profile", "path", path, "error", err)
			return nil
		}
		rel := strings.TrimPrefix(path, root+"/")
		base := filepath.Base(path)
		p.FileName = base
		p.RelPath = rel
		p.Origin = OriginEmbedded
		l.byFile[rel] = &p
		if _, exists := l.byBase[base]; !exists {
			l.byBase[base] = rel
		}
		return nil
	})
}

func (l *Loader) readDir() error {
	return filepath.WalkDir(l.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading profile %s: %w", path, err)
		}
		var p Profile
		if err := yaml.Unmarshal(data, &p); err != nil {
			l.logger.Warn("Skipping invalid profile", "path", config.SanitizeLogValue(path), "error", err)
			return nil
		}
		rel, err := filepath.Rel(l.dir, path)
		if err != nil {
			rel = path
		}
		base := filepath.Base(path)
		p.FileName = base
		p.RelPath = filepath.ToSlash(rel)
		p.Origin = OriginOverride
		l.byFile[p.RelPath] = &p
		if _, exists := l.byBase[base]; !exists {
			l.byBase[base] = p.RelPath
		}
		return nil
	})
}

// prepend returns a freshly allocated slice containing head followed by tail.
// It never writes into head's or tail's backing array: it always allocates a
// new one up front and only reads from its arguments. This matters because
// head is typically a cached, already-resolved parent's slice that may be
// shared by more than one child through l.resolved; appending directly onto
// it (e.g. append(head, tail...)) would reuse head's backing array whenever
// head has spare capacity, letting one child's merge silently overwrite
// another's.
// markExtended returns a copy of entries with FromExtended set, so a resolved
// profile can tell an entry it inherited from one its own file declares.
//
// It copies rather than writing in place because a resolved parent is cached
// and may be extended by more than one child; the flag belongs to the child's
// view of the entry, not to the parent's.
func markExtended(entries []MetricEntry) []MetricEntry {
	if len(entries) == 0 {
		return nil
	}
	out := make([]MetricEntry, len(entries))
	copy(out, entries)
	for i := range out {
		out[i].FromExtended = true
	}
	return out
}

func prepend[T any](head, tail []T) []T {
	if len(head) == 0 && len(tail) == 0 {
		return nil
	}
	out := make([]T, 0, len(head)+len(tail))
	out = append(out, head...)
	out = append(out, tail...)
	return out
}

// Resolve returns the fully-merged profile for the given key, resolving all
// extends recursively and then the metric names two symbols claim at once.
// key may be a relative path (e.g. "cisco/cisco-catalyst.yml") or a bare basename
// (e.g. "system-mib.yml") as used in extends references.
//
// A bare basename goes through the basename index, so a bundled
// `extends: system-mib.yml` keeps resolving to _general/system-mib.yml
// whatever an override directory holds at its root. Consulting the path index
// first let one mislocated file reparent every profile extending that name.
// A key with a path separator stays an exact path lookup.
func (l *Loader) Resolve(key string) (*Profile, error) {
	p, err := l.resolveMerged(key)
	if err != nil {
		return nil, err
	}
	return l.dedupe(p), nil
}

// resolveMerged returns the merged profile before duplicate metric names are
// resolved. Inheritance reads this one: pruning a parent would settle a
// contest among the parent's symbols alone, and a child's own symbol has to be
// able to beat an inherited one.
func (l *Loader) resolveMerged(key string) (*Profile, error) {
	if !strings.Contains(key, "/") {
		if rel, ok := l.byBase[key]; ok {
			key = rel
		}
	}
	return l.resolvePath(key)
}

// dedupe returns p with duplicate metric names resolved, cached against the
// merged profile it came from.
func (l *Loader) dedupe(p *Profile) *Profile {
	if out, ok := l.deduped[p.RelPath]; ok {
		return out
	}
	out := pruneDuplicates(p, l.logger)
	l.deduped[p.RelPath] = out
	return out
}

// resolvePath resolves one profile by its exact relative path. Every profile
// the loader holds is reachable this way, including one whose basename another
// profile already owns in byBase.
func (l *Loader) resolvePath(key string) (*Profile, error) {
	if p, ok := l.resolved[key]; ok {
		return p, nil
	}
	if l.resolving[key] {
		return nil, fmt.Errorf("circular extends dependency detected for %q", key)
	}
	p, ok := l.byFile[key]
	if !ok {
		return nil, fmt.Errorf("profile %q not found", key)
	}

	l.resolving[key] = true
	defer delete(l.resolving, key)

	merged := &Profile{
		FileName:        p.FileName,
		RelPath:         p.RelPath,
		Origin:          p.Origin,
		ReplacesBundled: p.ReplacesBundled,
		Provider:        p.Provider,
		SysObjectID:     p.SysObjectID,
		// Both redirect forms are the declaring file's own. The extends
		// merge below carries metrics and tags and touches neither, which is
		// what upstream does too, so a redirect never crosses an extends edge
		// and there is no parent list for a child's to interleave with.
		Matches:          p.Matches,
		MatchesList:      p.MatchesList,
		Traps:            p.Traps,
		NoUseBulkWalkAll: p.NoUseBulkWalkAll,
	}

	// Resolve and merge parent profiles (extends) first
	for _, parentName := range p.Extends {
		parent, err := l.resolveMerged(parentName)
		if err != nil {
			l.logger.Warn("Could not resolve extended profile, skipping", "parent", parentName, "child", key, "error", err)
			continue
		}
		// Parent metrics/tags are prepended. A resolved parent is cached in
		// l.resolved and may be extended by more than one sibling, so its
		// slice must never be the destination of an append: append(x, ...)
		// reuses x's backing array whenever x has spare capacity, and a
		// second sibling writing into that spare capacity would silently
		// corrupt the metrics of the first sibling's already-cached profile.
		// prepend allocates a fresh backing array up front and only ever
		// reads from parent.Metrics/parent.MetricTags, so no two resolved
		// profiles can end up sharing an array.
		merged.Metrics = prepend(markExtended(parent.Metrics), merged.Metrics)
		merged.MetricTags = prepend(parent.MetricTags, merged.MetricTags)
		// The flag describes the agent rather than one metric, so a parent that
		// disables bulk walking disables it for everything extending it. A
		// child cannot clear it: the zero value is indistinguishable from an
		// absent field, so letting a child win would clear it everywhere.
		merged.NoUseBulkWalkAll = merged.NoUseBulkWalkAll || parent.NoUseBulkWalkAll
	}

	// Append this profile's own metrics/tags after parent's. merged.Metrics
	// (nil, or a slice built exclusively by prepend above) is owned solely
	// by this call, so appending onto it here cannot alias another
	// profile's slice.
	merged.Metrics = append(merged.Metrics, p.Metrics...)
	merged.MetricTags = append(merged.MetricTags, p.MetricTags...)

	l.resolved[key] = merged
	return merged, nil
}

// AllResolved resolves every loaded profile, settles the metric names two of
// its symbols claim at once, and returns them in relative-path order. Profiles
// that fail to resolve are logged and skipped.
//
// The order is sorted rather than map order because the Matcher indexes this
// slice and has to break ties between profiles claiming the same key. Map order
// would decide those ties differently on every restart.
func (l *Loader) AllResolved() ([]*Profile, error) {
	l.reportFiles()
	names := slices.Sorted(maps.Keys(l.byFile))
	result := make([]*Profile, 0, len(names))
	for _, name := range names {
		p, err := l.resolvePath(name)
		if err != nil {
			l.logger.Warn("Failed to resolve profile", "file", name, "error", err)
			continue
		}
		p = l.dedupe(p)
		reportInertProfile(p, l.logger)
		result = append(result, p)
	}
	return result, nil
}

// reportFiles warns about what the loaded files declare and this loader cannot
// read. It runs on the files as written rather than on the resolved profiles: a
// base profile's entries are prepended to every profile extending it, so
// reporting after resolution would name the same entry once per child.
func (l *Loader) reportFiles() {
	for _, rel := range slices.Sorted(maps.Keys(l.byFile)) {
		reportUnreadableFlatEntries(l.byFile[rel], rel, l.logger)
		reportUnindexableSysObjectID(l.byFile[rel], rel, l.logger)
		reportEnumCollisions(l.byFile[rel], rel, l.logger)
	}
}

// enumOwner is one enum and the declaration that carries it.
type enumOwner struct {
	// kind is "symbol" or "column", and is the log key the owner is named under.
	kind string
	name string
	enum Enum
}

// enumOwners returns every enum a profile declares, in the order written: the
// scalar and table symbols of each metric entry, and the tag columns of the
// entries and of the profile itself. A tag writing its column's OID and name
// directly on the tag declares no enum, so there is none to collect there.
func enumOwners(p *Profile) []enumOwner {
	var out []enumOwner
	tags := func(mts []MetricTag) {
		for i := range mts {
			col := mts[i].Column
			if col == nil {
				col = mts[i].Symbol
			}
			if col == nil || col.Enum.Len() == 0 {
				continue
			}
			out = append(out, enumOwner{kind: "column", name: col.Name, enum: col.Enum})
		}
	}
	for _, entry := range p.Metrics {
		syms := entry.Symbols
		if entry.Symbol != nil {
			syms = append([]Symbol{*entry.Symbol}, syms...)
		}
		for _, sym := range syms {
			if sym.Enum.Len() == 0 {
				continue
			}
			out = append(out, enumOwner{kind: "symbol", name: sym.Name, enum: sym.Enum})
		}
		tags(entry.MetricTags)
	}
	tags(p.MetricTags)
	return out
}

// reportEnumCollisions names an enum value more than one member carries. The
// label is dropped rather than decided by iteration order, so the attribute it
// would have carried is missing from every device the profile matches, and
// only the profile can say which of the two names the device meant.
func reportEnumCollisions(p *Profile, rel string, logger *slog.Logger) {
	for _, owner := range enumOwners(p) {
		for _, dup := range owner.enum.Duplicated() {
			logger.Warn("SNMP profile enum gives one value to more than one member, that value is left unlabelled",
				"value", dup.Value,
				"members", dup.Names,
				owner.kind, config.SanitizeLogValue(owner.name),
				"file", config.SanitizeLogValue(rel))
		}
	}
}

// reportUnindexableSysObjectID names a sysobjectid the Matcher can index
// neither as an exact OID nor as a wildcard prefix. The profile still loads and
// still reports on itself, so a pattern in that state looks from the outside
// exactly like a device the bundled set does not cover, and every metric behind
// it is unreachable. No bundled pattern is in that state today, so a refresh
// that introduces one is visible rather than silently inert.
func reportUnindexableSysObjectID(p *Profile, rel string, logger *slog.Logger) {
	for _, raw := range p.SysObjectID {
		oid := normalizeOID(raw)
		if !unindexableSysObjectID(oid) {
			continue
		}
		logger.Warn("SNMP profile sysobjectid cannot be indexed, it will match no device",
			"sysobjectid", config.SanitizeLogValue(oid),
			"file", config.SanitizeLogValue(rel))
	}
}

// reportUnreadableFlatEntries names a flat metric entry that was not read as a
// symbol. The profile goes on claiming the device, so an entry that yields
// nothing is a metric the operator waits for and never sees.
func reportUnreadableFlatEntries(p *Profile, rel string, logger *slog.Logger) {
	for i := range p.Metrics {
		reason := flatEntryReason(&p.Metrics[i])
		if reason == "" {
			continue
		}
		logger.Warn("Ignoring metric entry this collector cannot read",
			"reason", reason,
			"metric", config.SanitizeLogValue(p.Metrics[i].Name),
			"oid", config.SanitizeLogValue(p.Metrics[i].OID),
			"file", config.SanitizeLogValue(rel))
	}
}

// reportInertProfile warns when a profile declares metrics the collector can
// never read. Every metric entry has to carry a symbol, a symbols block or a
// table; an entry with none of those parses cleanly and yields nothing, which
// is what a profile written against a different schema looks like from here.
// A profile with no metric entries at all is not reported: the bundled set
// includes base profiles that exist only to be inherited.
func reportInertProfile(p *Profile, logger *slog.Logger) {
	if len(p.Metrics) == 0 {
		return
	}
	for _, m := range p.Metrics {
		if m.Symbol != nil || len(m.Symbols) > 0 || m.Table != nil {
			return
		}
	}
	logger.Warn("SNMP profile declares no metric the collector can read, it will yield nothing",
		"file", config.SanitizeLogValue(p.RelPath),
		"entries", len(p.Metrics),
		"sysobjectid_count", len(p.SysObjectID))
}

// Count returns the number of raw (unresolved) profiles loaded.
func (l *Loader) Count() int {
	return len(l.byFile)
}
