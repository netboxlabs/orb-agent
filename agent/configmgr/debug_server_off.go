//go:build !debug

package configmgr

import (
	"log/slog"

	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet"
)

// debugServer is a no-op stub when built without "-tags debug".
type debugServer struct{}

func startFleetDebugServer(_ *slog.Logger, _ *fleet.AuthTokenManager, _ chan<- struct{}) *debugServer {
	return nil
}

func (ds *debugServer) stop()        {}
func (ds *debugServer) addr() string { return "" }
