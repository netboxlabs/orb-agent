package config

import (
	"bytes"
	"errors"
	"log/slog"
	"regexp"

	"gopkg.in/yaml.v3"
)

// yaml.v3 ignores unrecognized keys, so a key written at the wrong nesting
// level decodes without complaint and is then dropped: the setting silently
// never takes effect, and nothing downstream can tell that apart from the
// option being absent. WarnUnknownPolicyKeys keeps the permissive decode and
// reports those keys instead.

// unknownFieldRe pulls the key and the type out of a yaml.TypeError entry,
// which reads: `field metrics_intervall not found in type config.PolicyConfig`.
// The key capture allows whitespace: `metrics interval: 60` is a valid YAML
// mapping key, and skipping it would hide the very mistake this warning exists
// to surface.
var unknownFieldRe = regexp.MustCompile(`field (.+) not found in type (\S+)$`)

// narrowedTypes are the blocks whose keys are a closed, documented set. The
// policy map carries operator-chosen names with no set to check against, so
// reporting those would fire on correct files and train operators to ignore
// the warning.
var narrowedTypes = map[string]bool{
	"config.Policy":       true,
	"config.PolicyConfig": true,
	"config.Scope":        true,
	"config.Target":       true,
	"config.TLSConfig":    true,
}

// WarnUnknownPolicyKeys logs one warning per unrecognized key in a policy's
// config, scope, target or tls block.
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
	for _, entry := range typeErr.Errors {
		match := unknownFieldRe.FindStringSubmatch(entry)
		if match == nil || !narrowedTypes[match[2]] {
			continue
		}
		logger.Warn("ignoring unrecognized policy key", "key", match[1], "detail", entry)
	}
}
