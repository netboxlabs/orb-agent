package pktvisor

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// The rules below are the ones the SNMP telemetry backend applies to a
// target's attributes, copied because they live in another Go module. They
// are checked before ApplyPolicy sends anything, because an update removes the
// running policy before it posts the new one, and a body pktvisord refuses
// would leave nothing running.

// Bounds on the attributes of a policy or a target. Every series repeats them.
const (
	// maxAttributes bounds the attributes one policy or target carries, the
	// policy's included.
	maxAttributes = 32
	// maxKeyBytes bounds the length of a key.
	maxKeyBytes = 128
	// maxStringBytes bounds the length of a string value.
	maxStringBytes = 256
	// maxTotalBytes bounds the keys and string values of one set together.
	maxTotalBytes = 1024
)

// attributes are operator-defined key/value pairs a policy puts on every
// series it produces.
type attributes map[string]any

// reservedAttribute reports the names pktvisor sets on its series itself, or
// refuses as labels (le and quantile belong to histograms and summaries).
func reservedAttribute(name string) bool {
	switch name {
	case "policy", "handler", "tap", "target", "device", "le", "quantile":
		return true
	}
	return false
}

// handlerLabels are the labels each pktvisor handler type sets on its own
// series (own_label_names in pktvisord). pktvisord refuses an attribute whose
// Prometheus name is one of them for any handler the policy runs. A type's
// versions share one list, so direction, which only v2 of dns and net sets,
// is refused for v1 too.
var handlerLabels = map[string][]string{
	"dhcp":     {"client", "server"},
	"dns":      {"direction", "lat", "lon", "geo_loc", "asn", "ecs", "qname", "port", "qtype", "rcode"},
	"flow":     {"device", "device_interface", "lat", "lon", "conversation", "geo_loc", "asn", "ip", "port", "ip_port", "dscp", "ecn", "interface"},
	"net":      {"direction", "lat", "lon", "geo_loc", "asn", "ipv4", "ipv6"},
	"netprobe": {"target", "status_code", "rcode"},
}

// ownLabels maps each label the body's handler modules set to the handler
// that sets it, the first in type order. Modules are read in the two forms
// pktvisord accepts: a mapping of module names, or a list of mappings from a
// module name. Every name of a list item counts, although pktvisord reads
// only the first, so the agent may refuse a key pktvisord takes, never the
// other way round.
func ownLabels(doc map[string]any) map[string]string {
	handlers, _ := asMap(doc["handlers"])
	var types []string
	add := func(name string, holder map[string]any) {
		if t, ok := moduleType(name, holder); ok {
			types = append(types, t)
		}
	}
	if list, ok := handlers["modules"].([]any); ok {
		for _, item := range list {
			one, _ := asMap(item)
			for name := range one {
				add(name, one)
			}
		}
	} else if modules, ok := asMap(handlers["modules"]); ok {
		for name, raw := range modules {
			module, _ := asMap(raw)
			add(name, module)
		}
	}
	slices.Sort(types)
	out := map[string]string{}
	for _, t := range types {
		for _, label := range handlerLabels[t] {
			if _, seen := out[label]; seen {
				continue
			}
			out[label] = t + " handler"
			if label == "direction" {
				out[label] = "version 2 of the " + t + " handler"
			}
		}
	}
	return out
}

// moduleType is the type of the module named name, held in holder: its type
// key, or, when that is not a string, the type key of the mapping under the
// module's own name, as pktvisord reads it.
func moduleType(name string, holder map[string]any) (string, bool) {
	if t, ok := holder["type"].(string); ok {
		return t, true
	}
	nested, _ := asMap(holder[name])
	t, ok := nested["type"].(string)
	return t, ok
}

// prometheusOwn reports whether a label name is one Prometheus sets or
// reserves itself: job and instance, every name starting with two
// underscores, and every name starting with otel_scope_.
func prometheusOwn(name string) bool {
	return name == "job" || name == "instance" ||
		strings.HasPrefix(name, "__") || strings.HasPrefix(name, "otel_scope_")
}

// prometheusName is the label a key becomes when OTLP is translated to
// Prometheus: every character outside [A-Za-z0-9_] replaced by an underscore,
// then "key_" put before a leading digit and "key" before a single leading
// underscore.
func prometheusName(key string) string {
	name := strings.Map(func(r rune) rune {
		if r == '_' || ('0' <= r && r <= '9') || ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') {
			return r
		}
		return '_'
	}, key)
	switch {
	case name == "":
		return name
	case '0' <= name[0] && name[0] <= '9':
		return "key_" + name
	case name[0] == '_' && !strings.HasPrefix(name, "__"):
		return "key" + name
	}
	return name
}

// startsWithLetter reports whether key starts with an ASCII letter.
func startsWithLetter(key string) bool {
	return key != "" && (('a' <= key[0] && key[0] <= 'z') || ('A' <= key[0] && key[0] <= 'Z'))
}

// isOrbKey reports whether the Orb platform strips the key from every series:
// lowercase "orb" followed by one byte that is not an ASCII letter or digit.
func isOrbKey(key string) bool {
	if len(key) < 4 || !strings.HasPrefix(key, "orb") {
		return false
	}
	c := key[3]
	return (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9')
}

// mergeAttributes lays a target's attributes over the policy's: a key the
// target sets takes the target's value. Neither map is written to.
func mergeAttributes(policy, target attributes) attributes {
	if len(policy) == 0 && len(target) == 0 {
		return nil
	}
	out := make(attributes, len(policy)+len(target))
	maps.Copy(out, policy)
	maps.Copy(out, target)
	return out
}

// validate checks the set's size, then every key and value in key order, and
// names the first one that cannot be exported. handlerOwn holds the labels the
// policy's handlers set, each with the handler that sets it (ownLabels).
//
// An empty string is refused rather than exported: a Prometheus-style backend
// reads an empty label as an absent one. Keys are compared in their
// Prometheus form too: a key landing on a reserved name would corrupt a label
// that identifies the series, and two keys landing on one name would corrupt
// each other.
func (a attributes) validate(handlerOwn map[string]string) error {
	if len(a) > maxAttributes {
		return fmt.Errorf("carries %d attributes, more than the limit of %d", len(a), maxAttributes)
	}
	promNames := make(map[string]string, len(a))
	total := 0
	for _, key := range slices.Sorted(maps.Keys(a)) {
		total += len(key)
		if s, ok := a[key].(string); ok {
			total += len(s)
		}
		switch {
		case key == "":
			return errors.New("attribute key is empty; give every attribute a name")
		case !utf8.ValidString(key):
			return fmt.Errorf("attribute key %q is not valid UTF-8", clip(key))
		case !startsWithLetter(key):
			return fmt.Errorf("attribute key %q must start with a letter (A-Z or a-z)", clip(key))
		case isOrbKey(key):
			return fmt.Errorf("attribute key %q is in the orb namespace, which the Orb platform sets and strips from every series", clip(key))
		case len(key) > maxKeyBytes:
			return fmt.Errorf("attribute key %q is %d bytes, longer than the limit of %d", clip(key), len(key), maxKeyBytes)
		case reservedAttribute(key):
			return fmt.Errorf("attribute key %q is reserved for the backend's own attributes", key)
		}
		prom := prometheusName(key)
		if reservedAttribute(prom) {
			return fmt.Errorf("attribute key %q becomes %q in Prometheus, a name reserved for the backend's own attributes", key, prom)
		}
		if handler, ok := handlerOwn[prom]; ok {
			if prom == key {
				return fmt.Errorf("attribute key %q is a label the %s sets itself", key, handler)
			}
			return fmt.Errorf("attribute key %q becomes %q in Prometheus, a label the %s sets itself", key, prom, handler)
		}
		if prometheusOwn(prom) {
			return fmt.Errorf("attribute key %q becomes %q in Prometheus, a label Prometheus sets itself", key, prom)
		}
		if other, dup := promNames[prom]; dup {
			return fmt.Errorf("attribute keys %q and %q both become %q in Prometheus; keep one", other, key, prom)
		}
		promNames[prom] = key
		if err := validateValue(key, a[key]); err != nil {
			return err
		}
	}
	if total > maxTotalBytes {
		return fmt.Errorf("carries %d bytes of attribute keys and string values, more than the limit of %d", total, maxTotalBytes)
	}
	return nil
}

// clip shortens a key for an error message, on a character boundary.
func clip(key string) string {
	const shown = 32
	if len(key) <= shown {
		return key
	}
	cut := shown
	for cut > 0 && !utf8.RuneStart(key[cut]) {
		cut--
	}
	return key[:cut] + "..."
}

// validateValue accepts the scalars a JSON body (numbers as float64) or a YAML
// one (int, float64, bool, string) carries.
func validateValue(key string, v any) error {
	const want = "give a string, a number or a boolean"
	switch v := v.(type) {
	case nil:
		return fmt.Errorf("attribute %q has no value; %s", key, want)
	case time.Time:
		return fmt.Errorf("attribute %q is a timestamp; quote it to send it as a string", key)
	case string:
		if v == "" {
			return fmt.Errorf("attribute %q is an empty string; leave the key out instead", key)
		}
		if !utf8.ValidString(v) {
			return fmt.Errorf("attribute %q is not valid UTF-8", key)
		}
		if len(v) > maxStringBytes {
			return fmt.Errorf("attribute %q is %d bytes, longer than the limit of %d", key, len(v), maxStringBytes)
		}
	case uint64:
		if v > math.MaxInt64 {
			return fmt.Errorf("attribute %q does not fit a 64-bit integer", key)
		}
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return fmt.Errorf("attribute %q is not a finite number", key)
		}
	case bool, int, int64:
	default:
		switch reflect.ValueOf(v).Kind() {
		case reflect.Map:
			return fmt.Errorf("attribute %q is a map; %s", key, want)
		case reflect.Slice, reflect.Array:
			return fmt.Errorf("attribute %q is a list; %s", key, want)
		}
		return fmt.Errorf("attribute %q is a %T; %s", key, v, want)
	}
	return nil
}

// asMap reads a decoded mapping. yaml.v3 decodes a mapping with a key that is
// not a string (101:, true:) as map[any]any, so both shapes are accepted, with
// the keys written the way yaml.Marshal writes them to pktvisord.
func asMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[fmt.Sprint(k)] = val
		}
		return out, true
	}
	return nil, false
}

// attributesOf reads the attributes of one item of the body. A missing or
// null entry means none; anything but a mapping is refused.
func attributesOf(holder map[string]any, item string) (attributes, error) {
	raw, present := holder["attributes"]
	if !present || raw == nil {
		return nil, nil
	}
	m, ok := asMap(raw)
	if !ok {
		return nil, fmt.Errorf("pktvisor attributes of %s must be a mapping of names to values, not a %T", item, raw)
	}
	return attributes(m), nil
}

// checkAttributes refuses a policy body whose attributes pktvisord would
// refuse: the policy's own, and for every target that sets some, the policy's
// merged with the target's. A body of any other shape is left to the checks
// that own it.
func checkAttributes(body any) error {
	doc, _ := asMap(body)
	policy, err := attributesOf(doc, "policy")
	if err != nil {
		return err
	}
	handlerOwn := ownLabels(doc)
	if err := policy.validate(handlerOwn); err != nil {
		return fmt.Errorf("pktvisor attributes of policy: %w", err)
	}

	input, _ := asMap(doc["input"])
	cfg, _ := asMap(input["config"])
	targets, _ := asMap(cfg["targets"])
	for _, name := range slices.Sorted(maps.Keys(targets)) {
		target, ok := asMap(targets[name])
		if !ok {
			continue
		}
		item := fmt.Sprintf("target %q", name)
		own, err := attributesOf(target, item)
		if err != nil {
			return err
		}
		if own == nil {
			continue
		}
		if err := mergeAttributes(policy, own).validate(handlerOwn); err != nil {
			return fmt.Errorf("pktvisor attributes of %s: %w", item, err)
		}
	}
	return nil
}
