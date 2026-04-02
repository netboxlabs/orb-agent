package fleet

import "context"

// DebugCredentials is the interface consumed by the debug trigger to force
// token rotation and inspect token state. It is implemented outside this
// package (by FleetConfigManager) so that fleet debug code has no dependency
// on the configmgr package.
type DebugCredentials interface {
	RotateCredentials(ctx context.Context) error
	LogCredentials()
}
