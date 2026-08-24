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
// The key capture allows whitespace: `discover modules: full` is a valid YAML
// mapping key, and skipping it would hide the very mistake this warning exists
// to surface.
// which reads: `line 5: field discover_modules not found in type config.Options`.
var unknownFieldRe = regexp.MustCompile(`field (.+) not found in type (\S+)$`)

// narrowedTypes are the blocks whose keys are a closed, documented set. The
// policy map, scope entries and surrounding YAML carry operator-chosen keys
// and anchors with no set to check against, so reporting those would fire on
// correct files and train operators to ignore the warning.
var narrowedTypes = map[string]bool{
	"config.PolicyConfig": true,
	"config.Options":      true,
}

// WarnUnknownPolicyKeys logs one warning per unrecognized key in a policy's
// config or options block, naming the path the key belongs at when it is a
// field of the options block one level down.
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
	optionKeys := yamlFieldNames(reflect.TypeFor[Options]())
	for _, entry := range typeErr.Errors {
		match := unknownFieldRe.FindStringSubmatch(entry)
		if match == nil || !narrowedTypes[match[2]] {
			continue
		}
		key := match[1]
		if match[2] == "config.PolicyConfig" && optionKeys[key] {
			logger.Warn("ignoring unrecognized config key",
				"key", key, "did_you_mean", "options."+key, "detail", entry)
			continue
		}
		logger.Warn("ignoring unrecognized policy key", "key", key, "detail", entry)
	}
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
