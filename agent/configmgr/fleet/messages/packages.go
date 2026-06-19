package messages

import "os"

// PackagesCredentialsRPCFunc is the function name for packages credentials RPC calls
const PackagesCredentialsRPCFunc = "packages_credentials"

// BundleSpec is the transport-facing shape of a bundle delivered over MQTT.
// It maps to filesmgr.FileSpec in handlePackages. A nil Extract means "omitted"
// and defaults to true (bundles are tarballs); an explicit false is honored.
type BundleSpec struct {
	Name       string      `json:"name"`
	Version    string      `json:"version"`
	URL        string      `json:"url"`
	SHA256     string      `json:"sha256"`
	ExpiresAt  int64       `json:"expires_at"`
	Extract    *bool       `json:"extract,omitempty"`
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
