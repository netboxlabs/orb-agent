package policy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
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
