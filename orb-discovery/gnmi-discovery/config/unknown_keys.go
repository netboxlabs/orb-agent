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
// Every inheritable field a target can override — tls, username, password and
// origin — is a pointer so that nil can mean "inherit the scope's value", and a
// null node unmarshals to exactly that nil. So an operator who writes a bare
// `tls:` or `origin:` to mean "nothing here" gets the opposite: the scope's
// value, complete with whatever credential, skip_verify or vendor origin it
// carries. yaml.v3 gives `key:` and `key: null` the same nil, so the distinction
// is invisible after unmarshalling and has to be caught on the raw document.
//
// All four are checked. Leaving origin out was its own bug: a target meant to
// use origin-less paths silently took the scope's vendor origin, and the failure
// then surfaced as its Subscribe or Get paths being rejected by the device, with
// nothing connecting that back to the policy.
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
	// Through mapEntries, not policies.Content: a policies map may itself import
	// entries with `<<`, and reading the raw content visits the merge key instead
	// of the policies it brought in.
	for _, entry := range mapEntries(policies, maxMergeDepth) {
		name, body := entry[0].Value, entry[1]
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
			// scope's value is inherited. Only an empty string is present, and the
			// guidance differs per field because what "" means differs.
			for _, f := range []struct{ key, fix string }{
				{"username", `write username: "" to connect without one`},
				{"password", `write password: "" to connect without one`},
				{"origin", `write origin: "" for origin-less paths`},
			} {
				warnIfNull(logger, target, name, host, f.key,
					"empty "+f.key+" key inherits the scope's value; "+f.fix)
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

// mapEntries returns a mapping's effective key/value pairs, following aliases
// and `<<` merge keys the way the decoder does.
//
// This is the primitive; both the lookup below and the policy enumeration are
// expressed through it. They were separate once, and the split was the bug: the
// lookup learned to resolve merges while the enumeration still read
// node.Content directly, so policies imported into the map through `<<` were
// decoded normally and never walked at all.
//
// Precedence is YAML's own: an explicit key beats anything merged, and among
// merge sources the earlier entry wins. Both fall out of taking the first
// occurrence of a name and ignoring the rest.
func mapEntries(node *yaml.Node, depth int) [][2]*yaml.Node {
	node = resolveAlias(node)
	if node == nil || node.Kind != yaml.MappingNode || depth <= 0 {
		return nil
	}

	var out [][2]*yaml.Node
	seen := make(map[string]bool, len(node.Content)/2)
	var merged []*yaml.Node

	for i := 0; i+1 < len(node.Content); i += 2 {
		k, v := node.Content[i], node.Content[i+1]
		if k.Tag == mergeTag || k.Value == "<<" {
			merged = append(merged, v)
			continue
		}
		if seen[k.Value] {
			continue
		}
		seen[k.Value] = true
		out = append(out, [2]*yaml.Node{k, resolveAlias(v)})
	}

	for _, m := range merged {
		m = resolveAlias(m)
		if m == nil {
			continue
		}
		sources := []*yaml.Node{m}
		if m.Kind == yaml.SequenceNode {
			sources = m.Content
		}
		for _, src := range sources {
			for _, e := range mapEntries(src, depth-1) {
				if seen[e[0].Value] {
					continue
				}
				seen[e[0].Value] = true
				out = append(out, e)
			}
		}
	}
	return out
}

// maxMergeDepth bounds how far merge keys are followed. A merge chain is finite
// in any document yaml.v3 accepts, but this walker runs on operator-supplied
// input and must not be the thing that overflows the stack on a self-referential
// one.
const maxMergeDepth = 32

// mapValue returns the value node for key in a mapping node, or nil.
func mapValue(node *yaml.Node, key string) *yaml.Node {
	for _, e := range mapEntries(node, maxMergeDepth) {
		if e[0].Value == key {
			return e[1]
		}
	}
	return nil
}

// mergeTag is the tag yaml.v3 gives a `<<` key.
const mergeTag = "!!merge"

// resolveAlias follows an alias to the node it names.
func resolveAlias(n *yaml.Node) *yaml.Node {
	// Bounded rather than a bare loop: yaml.v3 rejects a recursive anchor, but
	// this walker runs on operator-supplied input and must not be the thing that
	// spins on a malformed document.
	for range 100 {
		if n == nil || n.Kind != yaml.AliasNode {
			return n
		}
		n = n.Alias
	}
	return nil
}
