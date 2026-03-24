package policy

import (
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnnotateEntitiesWithRunID_device(t *testing.T) {
	dev := &diode.Device{Name: diode.String("r1")}
	entities := []diode.Entity{dev}
	annotateEntitiesWithRunID(entities, "run-abc")
	require.Contains(t, dev.Metadata, "run_id")
	assert.Equal(t, "run-abc", dev.Metadata["run_id"])
}

func TestAnnotateEntitiesWithRunID_interfaceNestedDevice(t *testing.T) {
	dev := &diode.Device{Name: diode.String("core")}
	iface := &diode.Interface{
		Name:   diode.String("eth0"),
		Device: dev,
	}
	entities := []diode.Entity{iface}
	annotateEntitiesWithRunID(entities, "run-xyz")
	require.Contains(t, iface.Metadata, "run_id")
	assert.Equal(t, "run-xyz", iface.Metadata["run_id"])
	require.Contains(t, dev.Metadata, "run_id")
	assert.Equal(t, "run-xyz", dev.Metadata["run_id"])
}

func TestAnnotateEntitiesWithRunID_ipAssignedToInterface(t *testing.T) {
	dev := &diode.Device{Name: diode.String("d")}
	iface := &diode.Interface{Name: diode.String("gi0"), Device: dev}
	ip := &diode.IPAddress{
		Address:        diode.String("10.0.0.1/32"),
		AssignedObject: iface,
	}
	entities := []diode.Entity{ip}
	annotateEntitiesWithRunID(entities, "run-ip")
	require.Contains(t, ip.Metadata, "run_id")
	require.Contains(t, iface.Metadata, "run_id")
	require.Contains(t, dev.Metadata, "run_id")
}

func TestAnnotateEntitiesWithRunID_sharedDeviceVisitedOnce(t *testing.T) {
	dev := &diode.Device{Name: diode.String("shared")}
	if1 := &diode.Interface{Name: diode.String("a"), Device: dev}
	if2 := &diode.Interface{Name: diode.String("b"), Device: dev}
	entities := []diode.Entity{if1, if2}
	annotateEntitiesWithRunID(entities, "run-shared")
	assert.Equal(t, "run-shared", dev.Metadata["run_id"])
}
