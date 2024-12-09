package version_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netboxlabs/orb-discovery/network-discovery/version"
)

func TestVersion(t *testing.T) {
	v := version.GetBuildVersion()
	assert.Equal(t, "0.0.0", v)

	c := version.GetBuildCommit()
	assert.Equal(t, "unknown", c)
}
