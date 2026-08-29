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
	resolving map[string]bool     // cycle detection
	logger    *slog.Logger
}

func newEmptyLoader(dir string, logger *slog.Logger) *Loader {
	return &Loader{
		dir:       dir,
		byFile:    make(map[string]*Profile),
		byBase:    make(map[string]string),
		resolved:  make(map[string]*Profile),
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
			"file", rel, "override_dir", l.dir, "expected_path", want)
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
			l.logger.Warn("Skipping invalid profile", "path", path, "error", err)
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
func prepend[T any](head, tail []T) []T {
	if len(head) == 0 && len(tail) == 0 {
		return nil
	}
	out := make([]T, 0, len(head)+len(tail))
	out = append(out, head...)
	out = append(out, tail...)
	return out
}

// Resolve returns the fully-merged profile for the given key, resolving all extends recursively.
// key may be a relative path (e.g. "cisco/cisco-catalyst.yml") or a bare basename
// (e.g. "system-mib.yml") as used in extends references.
//
// A bare basename goes through the basename index, so a bundled
// `extends: system-mib.yml` keeps resolving to _general/system-mib.yml
// whatever an override directory holds at its root. Consulting the path index
// first let one mislocated file reparent every profile extending that name.
// A key with a path separator stays an exact path lookup.
func (l *Loader) Resolve(key string) (*Profile, error) {
	if !strings.Contains(key, "/") {
		if rel, ok := l.byBase[key]; ok {
			key = rel
		}
	}
	return l.resolvePath(key)
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
		Matches:         p.Matches,
	}

	// Resolve and merge parent profiles (extends) first
	for _, parentName := range p.Extends {
		parent, err := l.Resolve(parentName)
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
		merged.Metrics = prepend(parent.Metrics, merged.Metrics)
		merged.MetricTags = prepend(parent.MetricTags, merged.MetricTags)
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

// AllResolved resolves every loaded profile and returns them in relative-path
// order. Profiles that fail to resolve are logged and skipped.
//
// The order is sorted rather than map order because the Matcher indexes this
// slice and has to break ties between profiles claiming the same key. Map order
// would decide those ties differently on every restart.
func (l *Loader) AllResolved() ([]*Profile, error) {
	names := slices.Sorted(maps.Keys(l.byFile))
	result := make([]*Profile, 0, len(names))
	for _, name := range names {
		p, err := l.resolvePath(name)
		if err != nil {
			l.logger.Warn("Failed to resolve profile", "file", name, "error", err)
			continue
		}
		result = append(result, p)
	}
	return result, nil
}

// Count returns the number of raw (unresolved) profiles loaded.
func (l *Loader) Count() int {
	return len(l.byFile)
}
