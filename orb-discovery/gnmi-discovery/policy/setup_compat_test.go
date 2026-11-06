package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
)

func always(c codes.Code) func([]string) error {
	return func([]string) error { return status.Error(c, "refused") }
}

// Some devices refuse Capabilities and Get for good, with a code that also
// means "try again", and still serve Subscribe; one answers an RPC it does not
// implement with Unavailable. They ingest, and settle on one connection.
func TestDeviceRefusingCapabilitiesAndGetStillIngests(t *testing.T) {
	// A transient code redials through Capabilities before going on with _base;
	// PermissionDenied is the device's answer and goes on at once.
	dials := map[codes.Code]int32{codes.Unavailable: capsAttempts, codes.PermissionDenied: 1, codes.Unauthenticated: capsAttempts}
	for c, want := range dials {
		t.Run(c.String(), func(t *testing.T) {
			srv := &gnmiTarget{
				capsErr: func(int32) error { return status.Error(c, "refused") },
				getErr:  always(c),
			}
			_, client, d, _ := runAgainst(t, srv, config.ModeAuto, nil)

			requireSettled(t, client, d, want)
			dev := ingestedDevice(t, client)
			require.Equal(t, "sw1", *dev.Name)
		})
	}
}

// A device that refuses every Get but serves Subscribe ingests over the stream.
func TestDeviceRefusingGetStillIngests(t *testing.T) {
	for _, c := range []codes.Code{codes.Unavailable, codes.PermissionDenied, codes.Unauthenticated, codes.ResourceExhausted} {
		t.Run(c.String(), func(t *testing.T) {
			srv := &gnmiTarget{getErr: always(c)}
			r, client, d, _ := runAgainst(t, srv, config.ModeAuto, nil)

			requireSettled(t, client, d, 1)
			require.Equal(t, "on_change", targetStatus(t, r).ActiveMode)
			require.Equal(t, "MODEL-1", *ingestedDevice(t, client).DeviceType.Model)
		})
	}
}

// A device whose streaming service refuses every subscription with a code
// that also means "try again", while Get works, ingests over GET.
func TestDeviceRefusingSubscribeIngestsOverGet(t *testing.T) {
	for _, c := range []codes.Code{codes.Unavailable, codes.ResourceExhausted, codes.Unauthenticated} {
		t.Run(c.String(), func(t *testing.T) {
			srv := &gnmiTarget{subErr: always(c)}
			r, client, d, _ := runAgainst(t, srv, config.ModeAuto, nil)

			requireSettled(t, client, d, 1)
			require.Equal(t, "get", targetStatus(t, r).ActiveMode)
			require.Equal(t, "SN-0001", *ingestedDevice(t, client).Serial)
		})
	}
}
