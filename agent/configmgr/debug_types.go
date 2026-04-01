package configmgr

import "time"

// tokenStatusInfo is returned by the token-status debug endpoint.
type tokenStatusInfo struct {
	ExpiresAt       time.Time `json:"expires_at"`
	TimeUntilExpiry string    `json:"time_until_expiry"`
	Expired         bool      `json:"expired"`
	ExpiringSoon    bool      `json:"expiring_soon"`
}

// tokenRotationResult is returned by the force-token-rotation debug endpoint.
type tokenRotationResult struct {
	Status          string    `json:"status"`
	PreviousExpiry  time.Time `json:"previous_expiry,omitempty"`
	NewExpiry       time.Time `json:"new_expiry,omitempty"`
	TimeUntilExpiry string    `json:"time_until_expiry,omitempty"`
}

// debugServerOpts holds the callbacks the debug server needs, keeping it
// decoupled from concrete types like AuthTokenManager.
type debugServerOpts struct {
	reconnectChan chan<- struct{}
	tokenStatus   func() tokenStatusInfo                 // nil-safe: endpoint returns 501 when absent
	tokenRotate   func() (old, new time.Time, err error) // nil-safe: refreshes token without reconnecting
}
