package configmgr

import "time"

// tokenStatusInfo is returned by the token-status debug endpoint.
type tokenStatusInfo struct {
	ExpiresAt       time.Time `json:"expires_at"`
	TimeUntilExpiry string    `json:"time_until_expiry"`
	Expired         bool      `json:"expired"`
	ExpiringSoon    bool      `json:"expiring_soon"`
}

// debugServerOpts holds the callbacks the debug server needs, keeping it
// decoupled from concrete types like AuthTokenManager.
type debugServerOpts struct {
	reconnectChan chan<- struct{}
	tokenStatus   func() tokenStatusInfo                   // nil-safe: endpoint returns 501 when absent
	tokenRotate   func() (old, fresh time.Time, err error) // nil-safe: refreshes token without reconnecting
}
