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
// policy map and the surrounding YAML carry operator-chosen names and anchors
// with no set to check against, so reporting those would fire on correct files
// and train operators to ignore the warning.
//
// The scope and target blocks matter most here. A misspelled scope-level
// `usernme` is silently dropped by the permissive decode, and every target in
// the range then authenticates with no username at all — a whole subnet failing
// for a reason nothing reports.
var narrowedTypes = map[string]bool{
	"config.PolicyConfig": true,
	"config.Options":      true,
	"config.Scope":        true,
	"config.Target":       true,
	"config.TLSConfig":    true,

	// The defaults blocks, where a typo silently drops a NetBox default and the
	// entities land with the built-in value instead of the operator's.
	"config.Defaults":          true,
	"config.DeviceDefaults":    true,
	"config.InterfaceDefaults": true,
	"config.PrefixDefaults":    true,
	"config.VlanDefaults":      true,
	"config.IPAddressDefaults": true,
	"config.VRFDefaults":       true,
	"config.InterfacePattern":  true,
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

// WarnAmbiguousNullKeys reports an inheritable key written with nothing under it.
//
// Target.TLS, Username and Password are pointers so that nil can mean "inherit
// the scope's value", and a null node unmarshals to exactly that nil. So an
// operator who writes a bare `tls:` or `username:` to mean "nothing here" gets
// the opposite — the scope's value, complete with whatever credential or
// skip_verify it carries. yaml.v3 gives `key:` and `key: null` the same nil, so
// the distinction is invisible after unmarshalling and has to be caught on the
// raw document.
func WarnAmbiguousNullKeys(data []byte, logger *slog.Logger) {
	if logger == nil {
		return
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 {
		return
	}
	policies := mapValue(doc.Content[0], "policies")
	if policies == nil {
		return
	}
	// A mapping node interleaves keys and values, so names and bodies are read
	// two at a time.
	for i := 0; i+1 < len(policies.Content); i += 2 {
		name, body := policies.Content[i].Value, policies.Content[i+1]
		scope := mapValue(body, "scope")
		if scope == nil {
			continue
		}
		warnIfNull(logger, scope, name, "scope", "tls",
			"empty tls block inherits the scope's TLS settings; remove the key to inherit, or give it fields to override")
		targets := mapValue(scope, "targets")
		if targets == nil {
			continue
		}
		for _, target := range targets.Content {
			host := "?"
			if h := mapValue(target, "host"); h != nil {
				host = h.Value
			}
			warnIfNull(logger, target, name, host, "tls",
				"empty tls block inherits the scope's TLS settings; remove the key to inherit, or give it fields to override")
			// A bare `username:` reads as "no username" and does the opposite:
			// yaml.v3 decodes it to the same nil an omitted key produces, so the
			// scope's credential is inherited. Only an empty string is present.
			for _, key := range []string{"username", "password"} {
				warnIfNull(logger, target, name, host, key,
					"empty "+key+` key inherits the scope's value; write `+key+`: "" to connect without one`)
			}
		}
	}
}

func warnIfNull(logger *slog.Logger, node *yaml.Node, policy, where, key, msg string) {
	value := mapValue(node, key)
	if value == nil || value.Tag != "!!null" {
		return
	}
	logger.Warn(msg, "policy", policy, "target", where)
}

// mapValue returns the value node for key in a mapping node, or nil.
func mapValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}
