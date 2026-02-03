package messages

import (
	"time"
)

// CurrentSecretsSchemaVersion defines the current version of the secrets schema
const CurrentSecretsSchemaVersion = "1.0"

// Error codes for secret operations
const (
	ErrorCodeNotFound      = "NOT_FOUND"
	ErrorCodeForbidden     = "FORBIDDEN"
	ErrorCodeInvalidPath   = "INVALID_PATH"
	ErrorCodeTimeout       = "TIMEOUT"
	ErrorCodeInternalError = "INTERNAL_ERROR"
	ErrorCodeRateLimited   = "RATE_LIMITED"
)

// SecretRequest represents a single secret request in a SecretRequestMsg
type SecretRequest struct {
	Path    string `json:"path"`    // The path to the secret in the control plane's secret store
	Context string `json:"context"` // The context where the secret is used (policy ID, "config", or "backend")
}

// SecretRequestMsg represents a request for secrets
type SecretRequestMsg struct {
	SchemaVersion string          `json:"schema_version"`
	RequestID     string          `json:"request_id"` // UUID v4
	Timestamp     time.Time       `json:"timestamp"`
	Secrets       []SecretRequest `json:"secrets"`
}

// SecretValue represents a successfully retrieved secret
type SecretValue struct {
	Path     string            `json:"path"`
	Value    string            `json:"value"`
	Version  int               `json:"version"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SecretError represents an error for a failed secret retrieval
type SecretError struct {
	Path  string `json:"path"`
	Error string `json:"error"` // Human-readable error message
	Code  string `json:"code"`  // Machine-readable error code
}

// SecretResponseMsg represents a response to a secret request
type SecretResponseMsg struct {
	SchemaVersion string        `json:"schema_version"`
	RequestID     string        `json:"request_id"` // Matches the request_id from the original request
	Timestamp     time.Time     `json:"timestamp"`
	Status        string        `json:"status"`            // "success", "partial", "error"
	Secrets       []SecretValue `json:"secrets,omitempty"` // Omitted if status is "error"
	Errors        []SecretError `json:"errors,omitempty"`  // Omitted if status is "success"
}

// SecretUpdate represents a single secret update notification
type SecretUpdate struct {
	Path     string   `json:"path"`
	Version  int      `json:"version"`
	Contexts []string `json:"contexts"` // List of contexts (policy IDs) that use this secret
}

// SecretUpdateNotificationMsg represents a push notification for updated secrets
type SecretUpdateNotificationMsg struct {
	SchemaVersion string         `json:"schema_version"`
	Timestamp     time.Time      `json:"timestamp"`
	Updates       []SecretUpdate `json:"updates"`
}
