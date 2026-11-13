package backend_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netboxlabs/orb-agent/agent/backend"
)

// NotSent marks an error without changing what it says or what it wraps.
func TestNotSentKeepsTheErrorAndMarksIt(t *testing.T) {
	refused := &backend.HTTPError{StatusCode: 409, Message: "conflict"}
	err := backend.NotSent(fmt.Errorf("refused: %w", refused))

	assert.Equal(t, "refused: conflict", err.Error())
	var httpErr *backend.HTTPError
	assert.ErrorAs(t, err, &httpErr)
	assert.True(t, backend.PolicyNotSent(err))
	assert.True(t, backend.PolicyNotSent(fmt.Errorf("apply: %w", err)), "the mark survives wrapping")

	assert.False(t, backend.PolicyNotSent(refused))
	assert.False(t, backend.PolicyNotSent(errors.New("timed out")))
	assert.False(t, backend.PolicyNotSent(nil))
	assert.NoError(t, backend.NotSent(nil))
}
