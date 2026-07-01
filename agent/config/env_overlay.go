package config

import (
	"fmt"
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
// It returns an error on a scalar/parent collision (the same env root set both as a
// leaf value and as a parent of a deeper key) so the outcome is deterministic
// regardless of os.Environ ordering.
func envToNestedMap(environ []string) (map[string]any, error) {
	root := map[string]any{}
	for _, e := range environ {
		name, val, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		path, ok := envKeyToConfigPath(name)
		if !ok {
			continue
		}
		segments := strings.Split(path, ".") // safe: config keys are snake_case, never contain "."
		if err := nest(root, segments, val); err != nil {
			return nil, err
		}
	}
	return root, nil
}

// nest walks segments creating intermediate maps, setting val at the leaf.
// It errors on a collision: descending through a segment that already holds a
// scalar, or setting a leaf where a map already exists.
func nest(m map[string]any, segments []string, val string) error {
	for i, seg := range segments {
		last := i == len(segments)-1
		if last {
			if existing, ok := m[seg]; ok {
				if _, isMap := existing.(map[string]any); isMap {
					return fmt.Errorf("conflicting ORB_ override: %q is set both as a value and as a parent of deeper keys", strings.Join(segments, "."))
				}
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
