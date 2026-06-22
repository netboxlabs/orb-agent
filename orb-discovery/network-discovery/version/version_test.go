package version_test

import (
	"testing"

	"github.com/netboxlabs/orb-discovery/network-discovery/version"
	"github.com/stretchr/testify/assert"
)

func TestVersion(t *testing.T) {
	v := version.GetBuildVersion()
	assert.Equal(t, "0.0.0", v)

	c := version.GetBuildCommit()
	assert.Equal(t, "unknown", c)
}
