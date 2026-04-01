//go:build nodebug

package configmgr

import "log/slog"

// debugServer is a no-op stub when built with "-tags nodebug".
type debugServer struct{}

func startDebugServer(_ *slog.Logger, _ int, _ debugServerOpts) (*debugServer, error) {
	return nil, nil
}

func (ds *debugServer) stop() {}
func (ds *debugServer) addr() string { return "" }
