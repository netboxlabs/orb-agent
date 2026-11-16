package config

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/otel/attribute"
	"go.yaml.in/yaml/v3"
)

// Bounds on a target's attributes. Every exported datapoint repeats them, and
// one export carries every policy's telemetry, so their size times the series
// of a busy backend is what an export weighs. The agent's OTLP bridge receives
// at most 64 MiB, and the per-key limits alone would let one datapoint carry
// about 12 KiB, reaching that at some 5,300 datapoints; MaxTotalBytes holds a
// datapoint's attributes to 1 KiB.
const (
	// MaxAttributes bounds the attributes one target carries, the scope's
	// included.
	MaxAttributes = 32
	// MaxKeyBytes bounds the length of a key.
	MaxKeyBytes = 128
	// MaxStringBytes bounds the length of a string value.
	MaxStringBytes = 256
	// MaxTotalBytes bounds the keys and string values of one target's
	// attributes together, the scope's included.
	MaxTotalBytes = 1024
)

// prometheusOwn reports whether a label name is one Prometheus sets or
// reserves itself: job and instance, which it sets from the resource after
// copying a datapoint's attributes; every name starting with two underscores;
// and every name starting with otel_scope_, the labels it makes from the
// instrumentation scope, which every policy's series carry, its
// orb.policy.name attribute (otel_scope_orb_policy_name) included.
func prometheusOwn(name string) bool {
	return name == "job" || name == "instance" ||
		strings.HasPrefix(name, "__") || strings.HasPrefix(name, "otel_scope_")
}

// Attributes are operator-defined key/value pairs a policy puts on every
// series a target produces, exported as OTLP datapoint attributes. A value is
// a YAML scalar: a string, a boolean, an integer or a float, each exported as
// the OTel attribute type of the same kind.
type Attributes map[string]any

// wideInt marks an integer the policy wrote that does not fit int64, so
// Validate can refuse it by name.
type wideInt string

// notInt marks text the policy tagged !!int that is no integer at all.
type notInt string

// integerText is a decimal integer as YAML writes one: an optional sign, then
// digits, with the underscores the decoder ignores.
var integerText = regexp.MustCompile(`^[-+]?[0-9][0-9_]*$`)

// UnmarshalYAML decodes the block as a plain mapping would, merge keys and
// aliases included, and marks an integer past 64 bits. The decoder reads one
// past 2^64 as a float and one past 2^63 as an unsigned integer, and either
// would export a different number from the one written.
func (a *Attributes) UnmarshalYAML(node *yaml.Node) error {
	var nodes map[string]yaml.Node
	if err := node.Decode(&nodes); err != nil {
		return err
	}
	out := make(Attributes, len(nodes))
	for key, n := range nodes {
		for n.Kind == yaml.AliasNode && n.Alias != nil {
			n = *n.Alias
		}
		if v, marked := markInteger(&n); marked {
			out[key] = v
			continue
		}
		var v any
		if err := n.Decode(&v); err != nil {
			return err
		}
		out[key] = v
	}
	*a = out
	return nil
}

// markInteger returns the mark for a scalar Validate refuses as an integer:
// one tagged as an integer that does not fit int64 (wideInt) or is no integer
// (notInt), and integer text the decoder resolved to a float because it does
// not fit. A float the policy tagged as one stays a float.
func markInteger(n *yaml.Node) (any, bool) {
	if n.Kind != yaml.ScalarNode {
		return nil, false
	}
	plain := strings.ReplaceAll(n.Value, "_", "")
	switch n.ShortTag() {
	case "!!int":
		var i int64
		if n.Decode(&i) == nil {
			return nil, false
		}
		if _, err := strconv.ParseInt(plain, 0, 64); errors.Is(err, strconv.ErrRange) {
			return wideInt(n.Value), true
		}
		return notInt(n.Value), true
	case "!!float":
		// Parsed from the text: the float the decoder made of it can round
		// back into range, as -2^63-1 does.
		if n.Style&yaml.TaggedStyle != 0 || !integerText.MatchString(n.Value) {
			return nil, false
		}
		if _, err := strconv.ParseInt(plain, 10, 64); err != nil {
			return wideInt(n.Value), true
		}
	}
	return nil, false
}

// PrometheusName is the label a key becomes when OTLP is translated to
// Prometheus: every character outside [A-Za-z0-9_] replaced by an underscore,
// then "key_" put before a leading digit and "key" before a single leading
// underscore.
func PrometheusName(key string) string {
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

// startsWithLetter reports whether key starts with an ASCII letter, so that
// its Prometheus name is the key with its other characters replaced, never
// one translation prefixes.
func startsWithLetter(key string) bool {
	return key != "" && (('a' <= key[0] && key[0] <= 'z') || ('A' <= key[0] && key[0] <= 'Z'))
}

// MergeAttributes lays a target's attributes over the scope's: a key the
// target sets takes the target's value, and every other key keeps the scope's.
// Neither map is written to. Nil when the two set nothing between them.
func MergeAttributes(scope, target Attributes) Attributes {
	if len(scope) == 0 && len(target) == 0 {
		return nil
	}
	out := make(Attributes, len(scope)+len(target))
	maps.Copy(out, scope)
	maps.Copy(out, target)
	return out
}

// Validate checks the set's size, then every key and value in key order, and
// names the first one that cannot be exported. reserved reports the keys the
// backend sets itself; nil reserves none.
//
// An empty string is refused rather than exported: a Prometheus-style backend
// reads an empty label as an absent one, so it would mean one thing over OTLP
// and another there. A value that is not valid UTF-8 is refused because OTLP
// strings must be, and one such value would fail the whole export.
//
// Keys are compared in their Prometheus form too. Translation joins two
// labels that land on one name with ";", so a key landing on a reserved name
// would corrupt a label that identifies the series, and two keys landing on
// one name would corrupt each other. A key landing on a label Prometheus sets
// itself would be overwritten or refused there.
func (a Attributes) Validate(reserved func(string) bool) error {
	if len(a) > MaxAttributes {
		return fmt.Errorf("carries %d attributes, more than the limit of %d", len(a), MaxAttributes)
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
			return fmt.Errorf("attribute key %q is not valid UTF-8", key)
		case !startsWithLetter(key):
			return fmt.Errorf("attribute key %q must start with a letter (A-Z or a-z)", clip(key))
		case inOrbNamespace(key):
			return fmt.Errorf("attribute key %q is in the orb namespace, which the Orb platform sets and strips from every series", clip(key))
		case len(key) > MaxKeyBytes:
			return fmt.Errorf("attribute key %q is %d bytes, longer than the limit of %d", clip(key), len(key), MaxKeyBytes)
		case reserved != nil && reserved(key):
			return fmt.Errorf("attribute key %q is reserved: the backend sets it on its series", key)
		}
		prom := PrometheusName(key)
		if reserved != nil && reserved(prom) {
			return fmt.Errorf("attribute key %q becomes %q in Prometheus, which the backend sets on its series", key, prom)
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
	if total > MaxTotalBytes {
		return fmt.Errorf("carries %d bytes of attribute keys and string values, more than the limit of %d", total, MaxTotalBytes)
	}
	return nil
}

// inOrbNamespace reports whether key is one the Orb platform's enricher
// strips from every series before it stamps its own orb_* labels: lowercase
// orb followed by a byte that is not an ASCII letter or digit.
func inOrbNamespace(key string) bool {
	if len(key) < 4 || !strings.HasPrefix(key, "orb") {
		return false
	}
	c := key[3]
	return (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9')
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

func validateValue(key string, v any) error {
	const want = "give a string, a number or a boolean"
	switch v := v.(type) {
	case nil:
		return fmt.Errorf("attribute %q has no value; %s", key, want)
	case time.Time:
		// The decoder reads an unquoted date as a timestamp, and rendering it
		// back would not give the text that was written.
		return fmt.Errorf("attribute %q is a timestamp; quote it to send it as a string", key)
	case wideInt:
		return fmt.Errorf("attribute %q does not fit a 64-bit integer", key)
	case notInt:
		// The value is not quoted: it is unbounded, and may be a secret.
		return fmt.Errorf("attribute %q is tagged !!int, but its value is not an integer; %s", key, want)
	case string:
		if v == "" {
			return fmt.Errorf("attribute %q is an empty string; leave the key out instead", key)
		}
		if !utf8.ValidString(v) {
			return fmt.Errorf("attribute %q is not valid UTF-8", key)
		}
		if len(v) > MaxStringBytes {
			return fmt.Errorf("attribute %q is %d bytes, longer than the limit of %d", key, len(v), MaxStringBytes)
		}
	case uint64:
		if v > math.MaxInt64 {
			return fmt.Errorf("attribute %q does not fit a 64-bit integer", key)
		}
	case float64:
		// NaN equals nothing, itself included, so it cannot identify a series.
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return fmt.Errorf("attribute %q is not a finite number", key)
		}
	case bool, int, int64:
	default:
		// A nested mapping decodes as a map of its own, so the kind decides
		// rather than a list of types.
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

// KeyValues renders the attributes as OTel attributes, sorted by key. It is
// meant for attributes Validate accepted; a value of any other type is left
// out.
func (a Attributes) KeyValues() []attribute.KeyValue {
	if len(a) == 0 {
		return nil
	}
	out := make([]attribute.KeyValue, 0, len(a))
	for _, key := range slices.Sorted(maps.Keys(a)) {
		if kv, ok := keyValue(key, a[key]); ok {
			out = append(out, kv)
		}
	}
	return out
}

func keyValue(key string, v any) (attribute.KeyValue, bool) {
	switch v := v.(type) {
	case string:
		return attribute.String(key, v), true
	case bool:
		return attribute.Bool(key, v), true
	case int:
		return attribute.Int(key, v), true
	case int64:
		return attribute.Int64(key, v), true
	case uint64:
		if v <= math.MaxInt64 {
			return attribute.Int64(key, int64(v)), true
		}
	case float64:
		return attribute.Float64(key, v), true
	}
	return attribute.KeyValue{}, false
}

// Equal reports whether two sets of attributes export alike: the same keys,
// each with the same type and value.
func (a Attributes) Equal(b Attributes) bool {
	return slices.Equal(a.KeyValues(), b.KeyValues())
}
