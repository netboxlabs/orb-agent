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

func TestMatchPrefixAndDepth(t *testing.T) {
	keys, ok := MatchPrefix("/interfaces/interface[name=*]/state/counters", "/interfaces/interface[name=e1]")
	require.True(t, ok, "a deleted ancestor element matches the subscriptions under it")
	assert.Equal(t, "e1", keys["name"])
	_, ok = MatchPrefix("/interfaces/interface[name=*]/state/counters", "/components/component[name=x]")
	assert.False(t, ok)
	_, ok = MatchPrefix("/interfaces/interface[name=*]/state/counters", "/interfaces/interface[name=e1]/state/counters/in-octets")
	assert.False(t, ok, "a path below the subscription is not a prefix of it")
	assert.Equal(t, 4, Depth("/interfaces/interface[name=e1]/state/counters"))
}
