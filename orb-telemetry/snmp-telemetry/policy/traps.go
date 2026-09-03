package policy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/traps"
)

// validateTrapListen accepts host:port where host is empty, meaning every
// interface, or an IP literal. A hostname is rejected rather than resolved,
// for the same reason targets are not resolved: nothing here does DNS, and a
// name that resolved differently at each start would bind a different socket.
func validateTrapListen(listen string) error {
	if strings.TrimSpace(listen) == "" {
		return errors.New(`scope.traps.listen: required, for example "0.0.0.0:162"`)
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("scope.traps.listen: %w", err)
	}
	if host != "" {
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf("scope.traps.listen: host must be an IP address or empty, not %q", host)
		}
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("scope.traps.listen: port must be 1 to 65535, not %q", port)
	}
	return nil
}

// TrapPool hands a policy the socket its traps arrive on. A runner acquires
// as it starts, with the addresses its targets expand to and the v3 user
// each is polled with, and releases as it stops. It is a narrow interface rather than a
// back-reference to the pool, for the same reason Collector is.
type TrapPool interface {
	Acquire(listen, policy string, devices []traps.Device) (TrapLease, error)
}

// TrapLease is one runner's hold on one socket.
type TrapLease interface {
	Release()
}
