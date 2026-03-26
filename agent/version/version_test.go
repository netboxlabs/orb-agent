package version_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netboxlabs/orb-agent/agent/version"
)

func TestBuildVersion_DefaultsDev(t *testing.T) {
	// Without ldflags injection, buildVersion is empty and defaults to "dev"
	v := version.GetBuildVersion()
	assert.Equal(t, "dev", v)
}

func TestBuildCommit_EmptyInTestBinary(t *testing.T) {
	// go test does not embed VCS info; vcs.revision is only set via go build
	c := version.GetBuildCommit()
	assert.Empty(t, c)
}

func TestBuildTime_ZeroInTestBinary(t *testing.T) {
	// go test does not embed VCS info; vcs.time is only set via go build
	bt := version.GetBuildTime()
	assert.True(t, bt.IsZero())
}

func TestBuildBranch_EmptyWithoutLdflags(t *testing.T) {
	// Without ldflags injection, buildBranch is empty
	b := version.GetBuildBranch()
	assert.Empty(t, b)
}

func TestBuildModified_FalseInTestBinary(t *testing.T) {
	// go test does not embed VCS info; vcs.modified defaults to false
	assert.False(t, version.GetBuildModified())
}
