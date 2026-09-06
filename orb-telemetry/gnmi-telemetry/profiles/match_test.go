package profiles

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatchPathWildcardsKeys(t *testing.T) {
	keys, ok := MatchPath("/interfaces/interface[name=*]/state/counters", "/interfaces/interface[name=ethernet-1/1]/state/counters")
	require.True(t, ok)
	assert.Equal(t, map[string]string{"name": "ethernet-1/1"}, keys)
	_, ok = MatchPath("/interfaces/interface[name=*]/state/counters", "/interfaces/interface[name=e1]/state")
	assert.False(t, ok, "a shorter path is not a match")
	_, ok = MatchPath("/interfaces/interface[name=*]/state", "/interfaces/interface[name=e1]/state/counters")
	assert.False(t, ok, "a longer path is not a match")
	_, ok = MatchPath("/components/component[name=*]/state", "/interfaces/interface[name=e1]/state")
	assert.False(t, ok)
}

func TestMatchPathKeyedPattern(t *testing.T) {
	keys, ok := MatchPath("/system/cpus/cpu[index=ALL]/state", "/system/cpus/cpu[index=ALL]/state")
	require.True(t, ok)
	assert.Equal(t, map[string]string{"index": "ALL"}, keys)
	_, ok = MatchPath("/system/cpus/cpu[index=ALL]/state", "/system/cpus/cpu[index=1]/state")
	assert.False(t, ok, "a literal key must match exactly")
	keys, ok = MatchPath("/a[k=1][j=*]/b", "/a[j=2][k=1]/b")
	require.True(t, ok)
	assert.Equal(t, map[string]string{"k": "1", "j": "2"}, keys)
}

func TestMatchPathIgnoresModulePrefixes(t *testing.T) {
	keys, ok := MatchPath("/interfaces/interface[name=*]/state/counters", "/openconfig-interfaces:interfaces/interface[name=e1]/state/counters")
	require.True(t, ok)
	assert.Equal(t, "e1", keys["name"])
}

func TestSplitLeaf(t *testing.T) {
	leaf, keys, ok := SplitLeaf("/interfaces/interface[name=*]/state/counters", "/interfaces/interface[name=e1]/state/counters/in-octets")
	require.True(t, ok)
	assert.Equal(t, "in-octets", leaf)
	assert.Equal(t, "e1", keys["name"])
	leaf, _, ok = SplitLeaf("/system/cpus/cpu[index=*]/state", "/system/cpus/cpu[index=ALL]/state/total/instant")
	require.True(t, ok)
	assert.Equal(t, "total/instant", leaf, "a leaf may be nested under the subscription path")
	_, _, ok = SplitLeaf("/interfaces/interface[name=*]/state/counters", "/interfaces/interface[name=e1]/state/counters")
	assert.False(t, ok, "the subscription path itself is not below it")
	_, _, ok = SplitLeaf("/interfaces/interface[name=*]/state/counters", "/lldp/interfaces/interface[name=e1]/state/counters/frame-in")
	assert.False(t, ok)
}

// The parser decodes the escapes the transport writes around a bracket or a
// backslash in a key value: the bracket is part of the value, not a delimiter,
// and the value matches with the escape removed.
func TestParsePathDecodesEscapedDelimitersInKeyValues(t *testing.T) {
	elems := parsePath(`/interfaces/interface[name=a\]/b\[c\\d]/state/counters`)
	require.Len(t, elems, 4, "an escaped bracket does not close the key group, so the slash after it is part of the value")
	assert.Equal(t, map[string]string{"name": `a]/b[c\d`}, elems[1].keys)
	leaf, keys, ok := SplitLeaf("/interfaces/interface[name=*]/state/counters",
		`/interfaces/interface[name=a\]/b\[c\\d]/state/counters/in-octets`)
	require.True(t, ok)
	assert.Equal(t, "in-octets", leaf)
	assert.Equal(t, `a]/b[c\d`, keys["name"], "the attribute carries the value the device wrote")
}

// A keyed element below the subscription path is not a leaf: two entries of
// that list would reduce to the same leaf name under the same attributes and
// write one series. The update matches nothing instead.
func TestSplitLeafRefusesAKeyedElementBelowTheSubscription(t *testing.T) {
	_, _, ok := SplitLeaf("/interfaces/interface[name=*]",
		"/interfaces/interface[name=e1]/subinterfaces/subinterface[index=0]/state/x")
	assert.False(t, ok, "a list below the subscription path belongs in the subscription path")
	leaf, keys, ok := SplitLeaf("/interfaces/interface[name=*]/subinterfaces/subinterface[index=*]",
		"/interfaces/interface[name=e1]/subinterfaces/subinterface[index=0]/state/x")
	require.True(t, ok, "written into the subscription path, the list is matched and its key promotable")
	assert.Equal(t, "state/x", leaf)
	assert.Equal(t, map[string]string{"name": "e1", "index": "0"}, keys)
}

// A delete of a keyed list written without its key deletes every instance: it
// matches the keyed pattern element and carries no key, so the collector
// withdraws every series under it. An element written with keys is held to
// the exact rule, as an update is.
func TestMatchPrefixReadsAKeylessElementAsTheWholeList(t *testing.T) {
	keys, ok := MatchPrefix("/interfaces/interface[name=*]/state/counters", "/interfaces/interface")
	require.True(t, ok, "the whole list is an ancestor of every instance's subscription")
	assert.Empty(t, keys)
	keys, ok = MatchPrefix("/interfaces/interface[name=*]/state/counters", "/interfaces/interface[name=e1]/state")
	require.True(t, ok)
	assert.Equal(t, map[string]string{"name": "e1"}, keys)
	_, ok = MatchPrefix("/interfaces/interface[name=*]/state/counters", "/interfaces/interface[name=e1][type=x]")
	assert.False(t, ok, "an element carrying a key the pattern does not declare is held to the exact rule")
}

func TestMatchPrefixAndDepth(t *testing.T) {
	keys, ok := MatchPrefix("/interfaces/interface[name=*]/state/counters", "/interfaces/interface[name=e1]")
	require.True(t, ok, "a deleted ancestor element matches the subscriptions under it")
	assert.Equal(t, "e1", keys["name"])
	keys, ok = MatchPrefix("/interfaces/interface[name=*]/state/counters", "")
	assert.True(t, ok, "a delete of the data-tree root is an ancestor of every subscription")
	assert.Empty(t, keys, "the root carries no keys, so every series of the subscription is covered")
	_, ok = MatchPrefix("/interfaces/interface[name=*]/state/counters", "/")
	assert.True(t, ok, "the root written with its slash")
	_, ok = MatchPrefix("/interfaces/interface[name=*]/state/counters", "/components/component[name=x]")
	assert.False(t, ok)
	_, ok = MatchPrefix("/interfaces/interface[name=*]/state/counters", "/interfaces/interface[name=e1]/state/counters/in-octets")
	assert.False(t, ok, "a path below the subscription is not a prefix of it")
	assert.Equal(t, 4, Depth("/interfaces/interface[name=e1]/state/counters"))
}

// An update element matches a pattern element only when it carries exactly the
// keys the pattern declares. A list written without its key would otherwise
// match every element of that list, and since the pattern names no key there is
// nothing for an attribute to promote, so every element writes one shared
// series and each overwrites the last. Rejecting the match instead pushes the
// operator to write the key, which the wildcard rule then makes them promote.
func TestMatchRequiresExactlyThePatternsKeys(t *testing.T) {
	_, ok := MatchPath("/interfaces/interface/state/counters", "/interfaces/interface[name=eth0]/state/counters")
	assert.False(t, ok, "a keyless pattern element does not match a keyed update element")
	_, ok = MatchPath("/interfaces/interface[name=*]/state", "/interfaces/interface[name=e1][index=0]/state")
	assert.False(t, ok, "an update carrying a key the pattern does not declare is not a match")
	_, _, ok = SplitLeaf("/interfaces/interface/state/counters", "/interfaces/interface[name=e1]/state/counters/in-octets")
	assert.False(t, ok, "the leaf split holds the same rule")
	_, ok = MatchPrefix("/interfaces/interface/state/counters", "/interfaces/interface[name=e1]")
	assert.False(t, ok, "a delete of a keyed element is no prefix of a keyless pattern")
}
