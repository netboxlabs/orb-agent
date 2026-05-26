package messages

import "os"

// PackagesCredentialsRPCFunc is the function name for packages credentials RPC calls
const PackagesCredentialsRPCFunc = "packages_credentials"

// BundleSpec describes a single bundle delivered by filesmgr.Manager.
// Fields mirror filesmgr.FileSpec so the MQTT payload can fully drive
// how the bundle is fetched, placed, and permissioned on disk.
type BundleSpec struct {
	Name       string      `json:"name"`
	Version    string      `json:"version"`
	URL        string      `json:"url"`
	SHA256     string      `json:"sha256"`
	ExpiresAt  int64       `json:"expires_at"`
	Extract    bool        `json:"extract"`
	TargetPath string      `json:"target_path,omitempty"`
	Mode       os.FileMode `json:"mode,omitempty"`
}

// PackagesCredentialsRPCPayload is the payload for packages credentials RPC messages
type PackagesCredentialsRPCPayload struct {
	Bundles []BundleSpec `json:"bundles"`
}

// PackagesCredentialsRPC represents an RPC message for bundle delivery
type PackagesCredentialsRPC struct {
	SchemaVersion string                        `json:"schema_version"`
	Func          string                        `json:"func"`
	Payload       PackagesCredentialsRPCPayload `json:"payload"`
}
