package buildinfo

import (
	"encoding/json"
	"net/http"
)

// set via ldflags -X option at build time
var version = "unknown"

// minimum version of an agent that we allow to connect
const minAgentVersion string = "0.9.0-develop"

func GetVersion() string {
	return version
}

func GetMinAgentVersion() string {
	return minAgentVersion
}

// VersionInfo contains version endpoint response.
type VersionInfo struct {
	// Service contains service name.
	Service string `json:"service"`

	// Version contains service current version value.
	Version string `json:"version"`
}

// Version exposes an HTTP handler for retrieving service version.
func Version(service string) http.HandlerFunc {
	return http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		res := VersionInfo{service, version}

		data, _ := json.Marshal(res)

		rw.Write(data)
	})
}
