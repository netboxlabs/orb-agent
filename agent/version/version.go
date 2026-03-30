package version

import (
	"runtime/debug"
	"strconv"
	"time"
)

// buildVersion is set at build time via -ldflags "-X"
var buildVersion string

// buildBranch is set at build time via -ldflags "-X"
var buildBranch string

var (
	buildCommit   string
	buildTime     time.Time
	buildModified bool
)

func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			buildCommit = s.Value
		case "vcs.time":
			if t, err := time.Parse(time.RFC3339, s.Value); err == nil {
				buildTime = t
			}
		case "vcs.modified":
			buildModified, _ = strconv.ParseBool(s.Value)
		}
	}
}

// GetBuildVersion returns the build version of the orb-agent.
func GetBuildVersion() string {
	if buildVersion == "" {
		return "dev"
	}
	return buildVersion
}

// GetBuildCommit returns the full VCS commit hash.
func GetBuildCommit() string {
	return buildCommit
}

// GetBuildBranch returns the branch the binary was built from.
func GetBuildBranch() string {
	return buildBranch
}

// GetBuildTime returns the VCS commit timestamp.
func GetBuildTime() time.Time {
	return buildTime
}

// GetBuildModified returns whether the working tree had uncommitted changes at build time.
func GetBuildModified() bool {
	return buildModified
}
