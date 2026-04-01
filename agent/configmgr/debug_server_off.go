//go:build !debug

package configmgr

import "log/slog"

// debugServer is a no-op stub when built without "-tags debug".
type debugServer struct{}

func startDebugServer(_ *slog.Logger, _ debugServerOpts) (*debugServer, error) {
	return nil, nil
}

func (ds *debugServer) stop()        {}
func (ds *debugServer) addr() string { return "" }
