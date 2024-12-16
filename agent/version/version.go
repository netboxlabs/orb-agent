package version

import (
	_ "embed"
	"strings"
)

// Version is the version of the orb-agent
//
//go:embed BUILD_VERSION.txt
var buildVersion string

// Commit is the commit of the orb-agent
//
//go:embed BUILD_COMMIT.txt
var buildCommit string

// GetBuildVersion returns the build version of the orb-agent
func GetBuildVersion() string {
	return strings.TrimSpace(buildVersion)
}

// GetBuildCommit returns the build commit of the orb-agent
func GetBuildCommit() string {
	return strings.TrimSpace(buildCommit)
}
