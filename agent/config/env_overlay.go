package config

import "strings"

const (
	envPrefix    = "ORB_"
	envPathDelim = "__"
)

// envKeyToConfigPath maps an ORB_-prefixed environment variable name to a
// dot-delimited koanf key path under "orb", or returns ok=false to skip it.
// Only names containing the "__" path delimiter are treated as generic
// overrides; a bare ORB_ name (e.g. ORB_SECRETS_MANAGER) is reserved for an
// alias and is skipped here so it cannot clobber a whole subtree with a string.
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
		segments[i] = strings.ToLower(s)
	}
	return "orb." + strings.Join(segments, "."), true
}
