package config

import (
	"fmt"
	"log/slog"
	"strings"
)

const (
	envPrefix    = "ORB_"
	envPathDelim = "__"
)

// envKeyToConfigPath maps an ORB_-prefixed environment variable name to a
// dot-delimited config key path under "orb", or returns ok=false to skip it.
// Only names containing the "__" path delimiter are treated as generic
// overrides; a bare ORB_ name (e.g. ORB_SECRETS_MANAGER) has no "__" and is
// simply skipped here, so it cannot clobber a whole subtree with a string.
// A single "_" stays inside a key segment (e.g. secrets_manager, auth_args).
func envKeyToConfigPath(name string) (string, bool) {
	if !strings.HasPrefix(name, envPrefix) {
		return "", false
	}
	rest := strings.TrimPrefix(name, envPrefix)
	if !strings.Contains(rest, envPathDelim) {
		return "", false
	}
	if strings.Contains(rest, ".") {
		// An env name containing "." would mis-nest when the joined dot path
		// is re-split on "." in envToNestedMap, so it is not a valid override
		// name even though "." is legal in an env var name (e.g. via execve
		// or an --env-file).
		return "", false
	}
	segments := strings.Split(rest, envPathDelim)
	for i, s := range segments {
		if s == "" {
			// A trailing "__" or a doubled "__" produces an empty path
			// segment, which would otherwise nest a map under a scalar (or
			// vice versa) and surface as a confusing decode error. Skip it,
			// same as a bare name with no delimiter at all.
			return "", false
		}
		segments[i] = strings.ToLower(s)
	}
	return "orb." + strings.Join(segments, "."), true
}

// envToNestedMap turns ORB_*__* environment entries into a nested map[string]any
// rooted at "orb", suitable for a mapstructure overlay onto Config. It reuses
// envKeyToConfigPath for the naming rules (prefix, "__" delimiter, lowercasing).
// A "<NAME>=<value>" entry is split on the FIRST "=" only (values may contain "=").
// It returns an error on a collision — the same config path set as a leaf value
// both by a scalar/parent mismatch and by two different env names mapping to the
// same path (e.g. differing only in case) — so the outcome is deterministic
// regardless of os.Environ ordering.
//
// logger is nil-safe: it is used to debug-log ORB_-prefixed names that are
// skipped because they are not a valid override (bare name, empty segment, or
// a dotted name).
func envToNestedMap(environ []string, logger *slog.Logger) (map[string]any, error) {
	root := map[string]any{}
	for _, e := range environ {
		name, val, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		path, ok := envKeyToConfigPath(name)
		if !ok {
			if logger != nil && strings.HasPrefix(name, envPrefix) {
				logger.Debug("ignoring ORB_ environment variable that is not a valid config override", "name", name)
			}
			continue
		}
		if val == "" {
			// A set-but-empty ORB_* value is treated as unset, not as an
			// override to a zero value, so it never clobbers a file-set value.
			if logger != nil {
				logger.Debug("ignoring empty-valued ORB_ environment variable", "name", name)
			}
			continue
		}
		segments := strings.Split(path, ".") // safe: envKeyToConfigPath rejects names containing "."
		if err := nest(root, segments, val); err != nil {
			return nil, err
		}
	}
	return root, nil
}

// nest walks segments creating intermediate maps, setting val at the leaf.
// It errors on a collision: descending through a segment that already holds a
// scalar, setting a leaf where a map already exists, or setting a leaf that
// was already set as a leaf by a different env name mapping to the same path
// (env names are unique, so a same-path leaf duplicate can only come from two
// different names — always a real conflict, e.g. differing only in case).
func nest(m map[string]any, segments []string, val string) error {
	for i, seg := range segments {
		last := i == len(segments)-1
		if last {
			if existing, ok := m[seg]; ok {
				if _, isMap := existing.(map[string]any); isMap {
					return fmt.Errorf("conflicting ORB_ override: %q is set both as a value and as a parent of deeper keys", strings.Join(segments, "."))
				}
				return fmt.Errorf("conflicting ORB_ overrides: %q is set more than once", strings.Join(segments, "."))
			}
			m[seg] = val
			return nil
		}
		child, ok := m[seg]
		if !ok {
			next := map[string]any{}
			m[seg] = next
			m = next
			continue
		}
		childMap, ok := child.(map[string]any)
		if !ok {
			return fmt.Errorf("conflicting ORB_ override: %q is set both as a value and as a parent of deeper keys", strings.Join(segments[:i+1], "."))
		}
		m = childMap
	}
	return nil
}
