package pktvisor

import "github.com/netboxlabs/orb-agent/agent/backend"

// KeepTap marks a managed tap as one cleanup must leave alone.
func KeepTap(be backend.Backend, tap string) {
	be.(*pktvisorBackend).keepTap(tap)
}
