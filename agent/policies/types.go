package policies

import (
	"database/sql/driver"
	"time"
)

// PolicyData represents a policy
type PolicyData struct {
	ID                 string
	Datasets           map[string]bool
	GroupIDs           map[string]bool
	Name               string
	Backend            string
	Version            int32
	Data               interface{}
	State              PolicyState
	BackendErr         string
	LastScrapeBytes    int64
	LastScrapeTS       time.Time
	PreviousPolicyData *PolicyData
}

// GetDatasetIDs returns the dataset IDs
func (d *PolicyData) GetDatasetIDs() []string {
	keys := make([]string, len(d.Datasets))

	i := 0
	for k := range d.Datasets {
		keys[i] = k
		i++
	}
	return keys
}

// Policy state types
const (
	Unknown PolicyState = iota
	Running
	FailedToApply
	Offline
	NoTapMatch
)

// PolicyState represents the state of a policy
type PolicyState int

var policyStateMap = [...]string{
	"unknown",
	"running",
	"failed_to_apply",
	"offline",
	"no_tap_match",
}

var policyStateRevMap = map[string]PolicyState{
	"unknown":         Unknown,
	"running":         Running,
	"failed_to_apply": FailedToApply,
	"offline":         Offline,
	"no_tap_match":    NoTapMatch,
}

func (s PolicyState) String() string {
	return policyStateMap[s]
}

// Scan scans the value into the PolicyState
func (s *PolicyState) Scan(value interface{}) error {
	*s = policyStateRevMap[string(value.([]byte))]
	return nil
}

// Value returns the value of the PolicyState
func (s PolicyState) Value() (driver.Value, error) { return s.String(), nil }
