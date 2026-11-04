package config

import (
	"bytes"
	"errors"
	"log/slog"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
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

// entryLineRe pulls the line number off a yaml.TypeError entry.
var entryLineRe = regexp.MustCompile(`^line (\d+): `)

// WarnUnknownPolicyKeys logs one warning per unrecognized key in a policy's
// config or options block, naming the policy and, when the key is a field of
// the options block one level down, the path it belongs at.
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
	reportUnknownKeys(logger, typeErr.Errors, policyKeyOwners(data))
}

// reportUnknownKeys logs each entry of a strict decode's TypeError, once per
// policy that wrote the key.
func reportUnknownKeys(logger *slog.Logger, entries []string, owners map[keyAt][]string) {
	optionKeys := yamlFieldNames(reflect.TypeFor[Options]())
	reported := make(map[string]bool, len(entries))
	for _, entry := range entries {
		match := unknownFieldRe.FindStringSubmatch(entry)
		// An anchored block repeats its entry once per use; owners names each policy.
		if match == nil || !narrowedTypes[match[2]] || reported[entry] {
			continue
		}
		reported[entry] = true
		key := match[1]
		policies := owners[keyAt{line: entryLine(entry), key: key}]
		if len(policies) == 0 {
			policies = []string{"?"} // still reported when no policy can be named
		}
		for _, policy := range policies {
			if match[2] == "config.PolicyConfig" && optionKeys[key] {
				logger.Warn("ignoring unrecognized config key",
					"policy", policy, "key", key, "did_you_mean", "options."+key, "detail", entry)
				continue
			}
			logger.Warn("ignoring unrecognized policy key", "policy", policy, "key", key, "detail", entry)
		}
	}
}

// keyAt is a mapping key by the line it is written on, which is how a
// yaml.TypeError entry names it.
type keyAt struct {
	line int
	key  string
}

func entryLine(entry string) int {
	m := entryLineRe.FindStringSubmatch(entry)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// policyKeyOwners maps every key a policy uses, including keys it takes from an
// anchor or a `<<` merge, to the policies that use it, in document order.
//
// Keys are matched by line only, without their block type or column, so a
// payload posted to the backend API directly with several policies on one
// line, or with shared or overridden anchors, can name a policy that is not at
// fault. The agent sends one policy per request, in block style without anchors.
func policyKeyOwners(data []byte) map[keyAt][]string {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 {
		return nil
	}
	owners := map[keyAt][]string{}
	for _, entry := range mapEntries(mapValue(doc.Content[0], "policies"), maxMergeDepth) {
		policy := entry[0].Value
		// Visited per policy, so a block shared by reference is walked once each.
		visited := map[*yaml.Node]bool{}
		var walk func(n *yaml.Node)
		walk = func(n *yaml.Node) {
			n = resolveAlias(n)
			if n == nil || visited[n] {
				return
			}
			visited[n] = true
			if n.Kind == yaml.MappingNode {
				for i := 0; i+1 < len(n.Content); i += 2 {
					// A key written as an alias is decoded, and reported, under
					// the name it resolves to, on the alias's own line.
					key := n.Content[i]
					keyName := key.Value
					if r := resolveAlias(key); r != nil {
						keyName = r.Value
					}
					k := keyAt{line: key.Line, key: keyName}
					if names := owners[k]; len(names) == 0 || names[len(names)-1] != policy {
						owners[k] = append(names, policy)
					}
				}
			}
			for _, c := range n.Content {
				walk(c)
			}
		}
		walk(entry[1])
	}
	return owners
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
