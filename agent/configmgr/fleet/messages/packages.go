package messages


// PackagesCredentialsRPCFunc is the function name for packages credentials RPC calls
const PackagesCredentialsRPCFunc = "packages_credentials"

// BundleSpec describes a single bundle delivered by filesmanager
type BundleSpec struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	URL       string    `json:"url"`
	SHA256    string    `json:"sha256"`
	ExpiresAt int64     `json:"expires_at"`
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
