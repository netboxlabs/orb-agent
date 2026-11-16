package config

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.yaml.in/yaml/v3"
)

func decodePolicy(t *testing.T, text string) Policy {
	t.Helper()
	var p Policies
	require.NoError(t, yaml.Unmarshal([]byte(text), &p))
	require.Contains(t, p.Policies, "p1")
	return p.Policies["p1"]
}

func kvMap(kvs []attribute.KeyValue) map[string]attribute.Value {
	out := make(map[string]attribute.Value, len(kvs))
	for _, kv := range kvs {
		out[string(kv.Key)] = kv.Value
	}
	return out
}

// Each YAML scalar becomes the OTel attribute type of the same kind, so a
// number stays a number downstream rather than turning into text.
func TestAttributes_EachScalarKeepsItsType(t *testing.T) {
	p := decodePolicy(t, `
policies:
  p1:
    scope:
      attributes:
        site: dc-west
        quoted_number: "42"
        monitored: true
        rack_units: 42
        weight: 2.5
        whole_float: 3.0
`)
	got := kvMap(p.Scope.Attributes.KeyValues())
	assert.Equal(t, attribute.StringValue("dc-west"), got["site"])
	assert.Equal(t, attribute.StringValue("42"), got["quoted_number"], "a quoted number is a string")
	assert.Equal(t, attribute.BoolValue(true), got["monitored"])
	assert.Equal(t, attribute.Int64Value(42), got["rack_units"])
	assert.Equal(t, attribute.Float64Value(2.5), got["weight"])
	assert.Equal(t, attribute.Float64Value(3), got["whole_float"])
	require.NoError(t, p.Scope.Attributes.Validate(nil))
}

func TestAttributes_KeyValuesAreSortedByKey(t *testing.T) {
	kvs := Attributes{"b": "2", "a": "1", "c": "3"}.KeyValues()
	require.Len(t, kvs, 3)
	assert.Equal(t, []attribute.Key{"a", "b", "c"}, []attribute.Key{kvs[0].Key, kvs[1].Key, kvs[2].Key})
}

func TestAttributes_TargetBlockDecodes(t *testing.T) {
	p := decodePolicy(t, `
policies:
  p1:
    scope:
      targets:
        - host: 192.0.2.1
          attributes:
            role: edge
`)
	require.Len(t, p.Scope.Targets, 1)
	assert.Equal(t, Attributes{"role": "edge"}, p.Scope.Targets[0].Attributes)
}

func TestMergeAttributes_TargetOverridesScopeKeyByKey(t *testing.T) {
	scope := Attributes{"site": "dc-west", "tenant": "tenant-a"}
	target := Attributes{"site": "dc-east", "role": "edge"}
	got := MergeAttributes(scope, target)
	assert.Equal(t, Attributes{"site": "dc-east", "tenant": "tenant-a", "role": "edge"}, got)
	assert.Equal(t, Attributes{"site": "dc-west", "tenant": "tenant-a"}, scope, "the scope's map is not written to")
}

func TestMergeAttributes_ScopeOnly(t *testing.T) {
	assert.Equal(t, Attributes{"site": "dc-west"}, MergeAttributes(Attributes{"site": "dc-west"}, nil))
}

func TestMergeAttributes_TargetOnly(t *testing.T) {
	assert.Equal(t, Attributes{"role": "edge"}, MergeAttributes(nil, Attributes{"role": "edge"}))
}

func TestMergeAttributes_NeitherIsNil(t *testing.T) {
	assert.Nil(t, MergeAttributes(nil, Attributes{}))
}

func TestAttributes_EqualComparesTheExportedValues(t *testing.T) {
	assert.True(t, Attributes{"a": 1, "b": "x"}.Equal(Attributes{"b": "x", "a": int64(1)}))
	assert.False(t, Attributes{"a": 1}.Equal(Attributes{"a": 1.0}), "an integer and a float are different attribute values")
	assert.False(t, Attributes{"a": "1"}.Equal(Attributes{"a": "1", "b": "2"}))
	assert.True(t, Attributes(nil).Equal(Attributes{}))
}

// Every refusal names the key, so an operator can find it in a policy that
// sets dozens.
func TestAttributes_ValidateRefusesWhatCannotBeExported(t *testing.T) {
	cases := []struct {
		name  string
		attrs Attributes
		want  string
	}{
		{"empty key", Attributes{"": "x"}, "attribute key is empty"},
		{"invalid UTF-8 key", Attributes{"bad\xffkey": "x"}, `attribute key "bad\xffkey" is not valid UTF-8`},
		{"leading digit", Attributes{"2 cents": "x"}, `attribute key "2 cents" must start with a letter`},
		{"leading underscore", Attributes{"_site": "x"}, `attribute key "_site" must start with a letter`},
		{"leading non-ASCII letter", Attributes{"élan": "x"}, `attribute key "élan" must start with a letter`},
		{"null", Attributes{"site": nil}, `attribute "site" has no value`},
		{"map", Attributes{"site": map[string]any{"name": "x"}}, `attribute "site" is a map`},
		{"list", Attributes{"site": []any{"a", "b"}}, `attribute "site" is a list`},
		{"empty string", Attributes{"site": ""}, `attribute "site" is an empty string`},
		{"invalid UTF-8 value", Attributes{"site": "bad\xffvalue"}, `attribute "site" is not valid UTF-8`},
		{"NaN", Attributes{"ratio": math.NaN()}, `attribute "ratio" is not a finite number`},
		{"infinity", Attributes{"ratio": math.Inf(1)}, `attribute "ratio" is not a finite number`},
		{"past int64", Attributes{"count": uint64(math.MaxInt64) + 1}, `attribute "count" does not fit a 64-bit integer`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.attrs.Validate(nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestAttributes_ValidateRefusesReservedKeys(t *testing.T) {
	reserved := func(k string) bool { return k == "device_ip" }
	err := Attributes{"device_ip": "192.0.2.1"}.Validate(reserved)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `attribute key "device_ip" is reserved`)
	require.NoError(t, Attributes{"Device_IP": "x"}.Validate(reserved), "keys are case-sensitive")
}

// Validation walks the keys in order, so the same policy is refused with the
// same message every time.
func TestAttributes_ValidateReportsTheFirstKeyInOrder(t *testing.T) {
	attrs := Attributes{"zeta": nil, "alpha": nil, "mid": nil}
	for range 20 {
		err := attrs.Validate(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `"alpha"`)
	}
}

// The YAML parser refuses invalid UTF-8 in the document, but a !!binary key
// decodes to whatever bytes it encodes.
func TestAttributes_BinaryKeyWithInvalidUTF8IsRefused(t *testing.T) {
	p := decodePolicy(t, `
policies:
  p1:
    scope:
      attributes:
        ? !!binary /w==
        : x
`)
	err := p.Scope.Attributes.Validate(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is not valid UTF-8")
}

func TestAttributes_QuotedEmptyKeyIsRefused(t *testing.T) {
	p := decodePolicy(t, `
policies:
  p1:
    scope:
      attributes:
        "": x
`)
	err := p.Scope.Attributes.Validate(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "attribute key is empty")
}

func TestAttributes_DecodedNullMapAndListValuesAreRefused(t *testing.T) {
	for value, want := range map[string]string{"~": "has no value", "{name: x}": "is a map", "[a, b]": "is a list"} {
		p := decodePolicy(t, "policies:\n  p1:\n    scope:\n      attributes:\n        site: "+value+"\n")
		err := p.Scope.Attributes.Validate(nil)
		require.Error(t, err, value)
		assert.Contains(t, err.Error(), want)
	}
}

// An unquoted date decodes as a timestamp, which has no OTel attribute type.
// Rendering it back would not give the text the operator wrote.
func TestAttributes_UnquotedDateIsRefusedWithAHint(t *testing.T) {
	p := decodePolicy(t, "policies:\n  p1:\n    scope:\n      attributes:\n        installed: 2024-01-31\n")
	err := p.Scope.Attributes.Validate(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `attribute "installed" is a timestamp; quote it`)

	p = decodePolicy(t, "policies:\n  p1:\n    scope:\n      attributes:\n        installed: \"2024-01-31\"\n")
	require.NoError(t, p.Scope.Attributes.Validate(nil))
}

// The decoder reads an integer past 64 bits as a float, or as an unsigned one
// up to 2^64, and either would export a different number from the one
// written. It is refused, whatever the decoder made of it.
func TestAttributes_IntegersPastInt64AreRefused(t *testing.T) {
	for _, text := range []string{
		"99999999999999999999",
		"18446744073709551616",
		"18446744073709551615",
		"9223372036854775808",
		"-9223372036854775809",
		"!!int 99999999999999999999",
		"!!int 0x1FFFFFFFFFFFFFFFF",
	} {
		p := decodePolicy(t, "policies:\n  p1:\n    scope:\n      attributes:\n        count: "+text+"\n")
		err := p.Scope.Attributes.Validate(nil)
		require.Error(t, err, text)
		assert.Contains(t, err.Error(), `attribute "count" does not fit a 64-bit integer`, text)
	}

	// A float the policy tagged as one stays a float, however it is written.
	p := decodePolicy(t, "policies:\n  p1:\n    scope:\n      attributes:\n        count: !!float 99999999999999999999\n")
	require.NoError(t, p.Scope.Attributes.Validate(nil))
	assert.Equal(t, attribute.Float64Value(1e20), kvMap(p.Scope.Attributes.KeyValues())["count"])

	// Text tagged as an integer that is no integer at all is a type error, not
	// an integer out of range. The value is not quoted back: it is unbounded
	// and may have come from a secret.
	p = decodePolicy(t, "policies:\n  p1:\n    scope:\n      attributes:\n        count: !!int abc\n")
	err := p.Scope.Attributes.Validate(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `attribute "count" is tagged !!int, but its value is not an integer`)
	assert.NotContains(t, err.Error(), "abc")
	assert.NotContains(t, err.Error(), "does not fit")

	p = decodePolicy(t, `
policies:
  p1:
    scope:
      attributes:
        max: 9223372036854775807
        min: -9223372036854775808
        big_float: 1.5e20
        quoted: "99999999999999999999"
`)
	require.NoError(t, p.Scope.Attributes.Validate(nil))
	got := kvMap(p.Scope.Attributes.KeyValues())
	assert.Equal(t, attribute.Int64Value(math.MaxInt64), got["max"])
	assert.Equal(t, attribute.Int64Value(math.MinInt64), got["min"])
	assert.Equal(t, attribute.Float64Value(1.5e20), got["big_float"], "a float written as one stays a float")
	assert.Equal(t, attribute.StringValue("99999999999999999999"), got["quoted"])
}

// The decoding that finds those integers must not lose what the plain decode
// handles: a merge key, an alias, and a null block.
func TestAttributes_DecodingKeepsMergeKeysAndAliases(t *testing.T) {
	p := decodePolicy(t, `
policies:
  p1:
    scope:
      attributes: &common
        site: dc-west
        rack_units: 2
      targets:
        - host: 192.0.2.1
          attributes:
            <<: *common
            role: edge
        - host: 192.0.2.2
          attributes:
        - host: 192.0.2.3
          attributes: *common
`)
	assert.Equal(t, Attributes{"site": "dc-west", "rack_units": 2, "role": "edge"}, p.Scope.Targets[0].Attributes)
	assert.Nil(t, p.Scope.Targets[1].Attributes)
	assert.Equal(t, Attributes{"site": "dc-west", "rack_units": 2}, p.Scope.Targets[2].Attributes)

	var bad Policies
	assert.Error(t, yaml.Unmarshal([]byte("policies:\n  p1:\n    scope:\n      attributes: [a, b]\n"), &bad),
		"an attributes block that is not a mapping is a decode error, as before")
}

// Every series key and every datapoint repeats a target's attributes, so
// their size is bounded.
func TestAttributes_ValidateBoundsCountKeyAndValueSize(t *testing.T) {
	full := Attributes{}
	for i := range MaxAttributes {
		full[fmt.Sprintf("k%02d", i)] = "v"
	}
	require.NoError(t, full.Validate(nil))
	full["one_more"] = "v"
	err := full.Validate(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("%d attributes, more than the limit of %d", MaxAttributes+1, MaxAttributes))

	require.NoError(t, Attributes{strings.Repeat("k", MaxKeyBytes): "v"}.Validate(nil))
	err = Attributes{strings.Repeat("k", MaxKeyBytes+1): "v"}.Validate(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("is %d bytes, longer than the limit of %d", MaxKeyBytes+1, MaxKeyBytes))

	require.NoError(t, Attributes{"site": strings.Repeat("v", MaxStringBytes)}.Validate(nil))
	err = Attributes{"site": strings.Repeat("v", MaxStringBytes+1)}.Validate(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf(`attribute "site" is %d bytes, longer than the limit of %d`, MaxStringBytes+1, MaxStringBytes))
}

func TestPrometheusName(t *testing.T) {
	assert.Equal(t, "netbox_site", PrometheusName("netbox.site"))
	assert.Equal(t, "a_b_c_d", PrometheusName("a-b c/d"))
	assert.Equal(t, "site_", PrometheusName("siteé"), "one underscore per character, not per byte")
	assert.Equal(t, "Rack_9", PrometheusName("Rack_9"))
	assert.Equal(t, "key_2_cents", PrometheusName("2 cents"), "a leading digit gets key_")
	assert.Equal(t, "key_x", PrometheusName("_x"), "a single leading underscore gets key")
	assert.Equal(t, "key_x", PrometheusName(".x"), "a leading character replaced by an underscore gets key too")
	assert.Equal(t, "__name__", PrometheusName("__name__"), "a double underscore is kept")
}

// A key starting with a letter keeps its Prometheus name free of the prefixes
// translation adds, so "2 cents" can no longer pass beside "key_2_cents" and
// then land on the same label.
func TestAttributes_ValidateKeysCannotLandOnAPrefixedName(t *testing.T) {
	err := Attributes{"2 cents": "a", "key_2_cents": "b"}.Validate(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `attribute key "2 cents" must start with a letter`)
}

// OTLP-to-Prometheus translation replaces every character outside
// [A-Za-z0-9_] with an underscore and joins colliding labels with ";". A key
// that lands on a reserved name, or two keys that land on one name, would
// corrupt a label that identifies the series.
func TestAttributes_ValidateRefusesPrometheusNameCollisions(t *testing.T) {
	reserved := func(k string) bool { return k == "device_ip" || k == "netbox_id" }
	for _, key := range []string{"device.ip", "netbox.id", "device-ip"} {
		err := Attributes{key: "x"}.Validate(reserved)
		require.Error(t, err, key)
		assert.Contains(t, err.Error(), fmt.Sprintf(`attribute key %q becomes %q in Prometheus`, key, PrometheusName(key)))
	}

	err := Attributes{"netbox.site": "a", "netbox_site": "b"}.Validate(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `attribute keys "netbox.site" and "netbox_site" both become "netbox_site" in Prometheus`)

	require.NoError(t, Attributes{"netbox.site": "a", "netbox.tenant": "b"}.Validate(reserved))
}

// The per-key limits alone allow about 12 KiB of attributes on one datapoint,
// so the keys and string values of a target are also bounded together.
func TestAttributes_ValidateBoundsTheTotalSize(t *testing.T) {
	value := strings.Repeat("v", 200)
	full := Attributes{}
	for i := range 5 {
		full[fmt.Sprintf("k%02d", i)] = value // 3 + 200 bytes each
	}
	full["count"] = 9 // a number counts its key alone
	require.NoError(t, full.Validate(nil), "1020 bytes is within the limit")

	full["k05"] = value
	err := full.Validate(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("carries 1223 bytes of attribute keys and string values, more than the limit of %d", MaxTotalBytes))
}

// Prometheus sets job and instance from the resource after it copies the
// datapoint's attributes, reserves every name starting with two underscores,
// and adds otel_scope_ labels from the instrumentation scope, which every
// policy's series carry, so a key landing on one is lost or refused there.
func TestAttributes_ValidateRefusesPrometheusOwnLabels(t *testing.T) {
	for key, prom := range map[string]string{
		"job": "job", "instance": "instance",
		"otel_scope_name": "otel_scope_name", "otel.scope.version": "otel_scope_version",
		"otel.scope.schema_url": "otel_scope_schema_url", "otel_scope_policy_name": "otel_scope_policy_name",
		"otel-scope-anything": "otel_scope_anything",
	} {
		err := Attributes{key: "x"}.Validate(nil)
		require.Error(t, err, key)
		assert.Contains(t, err.Error(), fmt.Sprintf(`attribute key %q becomes %q in Prometheus, a label Prometheus sets itself`, key, prom), key)
	}
	// A __ name can only be reached by a key that does not start with a letter.
	for _, key := range []string{"__name__", "..meta", "_.x"} {
		err := Attributes{key: "x"}.Validate(nil)
		require.Error(t, err, key)
		assert.Contains(t, err.Error(), fmt.Sprintf(`attribute key %q must start with a letter`, key), key)
	}
	require.NoError(t, Attributes{"jobs": "x", "instance_id": "x", "netbox.job": "x", "otel_scope": "x", "netbox.otel_scope_name": "x"}.Validate(nil))
}

// A key too long to quote whole is cut on a character boundary, so the
// refusal stays readable text.
func TestAttributes_ALongKeyIsCutOnACharacterBoundary(t *testing.T) {
	key := "a" + strings.Repeat("é", 70) // 141 bytes; byte 32 falls inside a character
	err := Attributes{key: "x"}.Validate(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "141 bytes, longer than the limit")
	assert.NotContains(t, err.Error(), `\x`, "no character is split")
	assert.True(t, utf8.ValidString(err.Error()))
}
