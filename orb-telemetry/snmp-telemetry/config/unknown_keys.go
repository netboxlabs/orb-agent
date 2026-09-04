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
// which reads: `line 5: field snmp_timout not found in type config.PolicyConfig`.
// The key capture allows whitespace: `metrics interval: 60` is a valid YAML
// mapping key, and skipping it would hide the very mistake this warning exists
// to surface.
var unknownFieldRe = regexp.MustCompile(`field (.+) not found in type (\S+)$`)

// narrowedTypes are the blocks whose keys are a closed, documented set. The
// policy map carries operator-chosen names with no set to check against, so
// reporting those would fire on correct files and train operators to ignore
// the warning.
var narrowedTypes = map[string]bool{
	"config.Policy":         true,
	"config.PolicyConfig":   true,
	"config.Scope":          true,
	"config.Target":         true,
	"config.Authentication": true,
	"config.Traps":          true,
}

// credentialParents are the blocks that hold an authentication block one level
// down. A credential written directly under one of them is dropped, and the
// poll then fails the same way a wrong community string does.
var credentialParents = map[string]bool{
	"config.Scope":  true,
	"config.Target": true,
}

// WarnUnknownPolicyKeys logs one warning per unrecognized key in a policy's
// config, scope, target or authentication block, naming the path the key
// belongs at when it is a field of the authentication block one level down.
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
	authKeys := yamlFieldNames(reflect.TypeFor[Authentication]())
	for _, entry := range typeErr.Errors {
		match := unknownFieldRe.FindStringSubmatch(entry)
		if match == nil || !narrowedTypes[match[2]] {
			continue
		}
		key := match[1]
		if credentialParents[match[2]] && authKeys[key] {
			logger.Warn("ignoring unrecognized policy key",
				"key", key, "did_you_mean", "authentication."+key, "detail", entry)
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
