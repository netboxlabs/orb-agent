package config

import (
	"bytes"
	"errors"
	"log/slog"
	"reflect"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// yaml.v3 ignores unrecognized keys, so a key written at the wrong nesting
// level decodes without complaint and is then dropped: the setting silently
// never takes effect, and nothing downstream can tell that apart from the
// option being absent. WarnUnknownPolicyKeys keeps the permissive decode and
// reports those keys instead.

// unknownFieldRe pulls the key and the type out of a yaml.TypeError entry,
// which reads: `line 5: field fast_mode not found in type config.PolicyConfig`.
// The key capture allows whitespace: `fast mode: true` is a valid YAML mapping
// key, and skipping it would hide the very mistake this warning exists to
// surface.
var unknownFieldRe = regexp.MustCompile(`field (.+) not found in type (\S+)$`)

// narrowedTypes are the blocks whose keys are a closed, documented set. The
// policy map and surrounding YAML carry operator-chosen keys and anchors with
// no set to check against, so reporting those would fire on correct files and
// train operators to ignore the warning. Scope is excluded for the same
// reason it is in the other backends, and because its own keys are checked by
// the validation that already runs over them.
var narrowedTypes = map[string]bool{
	"config.PolicyConfig": true,
}

// suggestionSource is a block a misplaced config-level key may belong to.
type suggestionSource struct {
	label string
	keys  map[string]bool
}

// suggestionSources are the blocks a config-level key most often belongs to
// instead. Scope carries the bulk of this backend's tuning (ports, timing,
// scan_types), so a key landing on config is usually meant for it.
func suggestionSources() []suggestionSource {
	return []suggestionSource{
		{"defaults", yamlFieldNames(reflect.TypeFor[Defaults]())},
		{"scope", yamlFieldNames(reflect.TypeFor[Scope]())},
	}
}

// WarnUnknownPolicyKeys logs one warning per unrecognized key in a policy's
// config block, naming the block the key belongs to when it is a field of one
// of the blocks alongside it.
//
// Decoding happens a second time purely to collect the report; the error is
// never returned, so an unrecognized key stays non-fatal.
func WarnUnknownPolicyKeys(data []byte, logger *slog.Logger) {
	if logger == nil {
		return
	}
	var throwaway Policies
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var typeErr *yaml.TypeError
	if err := dec.Decode(&throwaway); err == nil || !errors.As(err, &typeErr) {
		// No unknown fields, or a syntax error the permissive decode reports.
		return
	}
	sources := suggestionSources()
	for _, entry := range typeErr.Errors {
		match := unknownFieldRe.FindStringSubmatch(entry)
		if match == nil || !narrowedTypes[match[2]] {
			continue
		}
		key := match[1]
		if label, ok := suggestFor(key, sources); ok {
			logger.Warn("ignoring unrecognized config key",
				"key", key, "did_you_mean", label+"."+key, "detail", entry)
			continue
		}
		logger.Warn("ignoring unrecognized config key", "key", key, "detail", entry)
	}
}

// suggestFor returns the label of the first block that accepts key.
func suggestFor(key string, sources []suggestionSource) (string, bool) {
	for _, source := range sources {
		if source.keys[key] {
			return source.label, true
		}
	}
	return "", false
}

// yamlFieldNames returns the yaml key each field of a struct accepts.
func yamlFieldNames(t reflect.Type) map[string]bool {
	names := make(map[string]bool)
	for field := range t.Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
		if name != "" && name != "-" {
			names[name] = true
		}
	}
	return names
}
