package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeriveStatus(t *testing.T) {
	t.Run("no runs returns unknown", func(t *testing.T) {
		assert.Equal(t, "unknown", deriveStatus(nil))
		assert.Equal(t, "unknown", deriveStatus([]*Run{}))
	})

	t.Run("no running runs returns latest run status", func(t *testing.T) {
		runs := []*Run{
			{Status: RunStatusFailed},
			{Status: RunStatusCompleted},
		}
		// findLatestRun returns runs[0] (newest-first sort assumed by caller)
		assert.Equal(t, "failed", deriveStatus(runs))
	})

	t.Run("any running returns running regardless of order", func(t *testing.T) {
		runs := []*Run{
			{Status: RunStatusCompleted},
			{Status: RunStatusRunning},
			{Status: RunStatusFailed},
		}
		assert.Equal(t, "running", deriveStatus(runs))
	})

	t.Run("single running run returns running", func(t *testing.T) {
		runs := []*Run{
			{Status: RunStatusRunning},
		}
		assert.Equal(t, "running", deriveStatus(runs))
	})
}
