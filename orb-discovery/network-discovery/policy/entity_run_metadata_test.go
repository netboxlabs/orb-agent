package policy

import (
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnnotateEntitiesWithRunID_ipAddress(t *testing.T) {
	ip := &diode.IPAddress{Address: diode.String("192.0.2.1/32")}
	annotateEntitiesWithRunID([]diode.Entity{ip}, "run-net-1")
	require.Contains(t, ip.Metadata, "run_id")
	assert.Equal(t, "run-net-1", ip.Metadata["run_id"])
}
