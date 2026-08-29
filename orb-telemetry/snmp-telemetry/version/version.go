package version

import (
	_ "embed"
	"strings"
)

// Version is the version of snmp-telemetry
//
//go:embed BUILD_VERSION.txt
var buildVersion string

// Commit is the commit of snmp-telemetry
//
//go:embed BUILD_COMMIT.txt
var buildCommit string

// GetBuildVersion returns the build version of snmp-telemetry
func GetBuildVersion() string {
	return strings.TrimSpace(buildVersion)
}

// GetBuildCommit returns the build commit of snmp-telemetry
func GetBuildCommit() string {
	return strings.TrimSpace(buildCommit)
}
