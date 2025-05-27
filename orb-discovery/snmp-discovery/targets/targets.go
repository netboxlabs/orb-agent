package targets

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Expand takes a target string and returns a slice of individual IP addresses or hostnames.
// It supports the following formats:
// - CIDR notation (e.g., 10.10.10.0/24)
// - IP range notation (e.g., 10.10.10.0-100)
// - Single IP address (e.g., 192.168.1.1)
// - Hostname (e.g., example.com)
func Expand(target string) ([]string, error) {
	// Try parsing as CIDR first
	if strings.Contains(target, "/") {
		return expandCIDR(target)
	}

	// Try parsing as IP range
	if strings.Contains(target, "-") {
		return expandIPRange(target)
	}

	// Try parsing as single IP
	if ip := net.ParseIP(target); ip != nil {
		return []string{target}, nil
	}

	// If not an IP, assume it's a hostname
	return []string{target}, nil
}

// expandCIDR expands a CIDR notation into individual IP addresses
func expandCIDR(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR notation: %w", err)
	}

	// Convert IPNet to IP
	ip := ipnet.IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("only IPv4 addresses are supported")
	}

	// Get network and broadcast addresses
	mask := ipnet.Mask
	network := ip.Mask(mask)
	broadcast := make(net.IP, len(network))
	for i := range network {
		broadcast[i] = network[i] | ^mask[i]
	}

	// Generate all IPs in range
	var ips []string
	ip = make(net.IP, len(network))
	copy(ip, network)

	// Include network address
	ips = append(ips, ip.String())

	// Generate all IPs including broadcast
	for inc(ip); ip.To4() != nil && !ip.Equal(broadcast); inc(ip) {
		ips = append(ips, ip.String())
	}

	// Include broadcast address
	ips = append(ips, broadcast.String())

	return ips, nil
}

// expandIPRange expands an IP range notation (e.g., 10.10.10.0-100) into individual IP addresses
func expandIPRange(rangeStr string) ([]string, error) {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid IP range format")
	}

	baseIP := net.ParseIP(strings.TrimSpace(parts[0]))
	if baseIP == nil {
		return nil, fmt.Errorf("invalid base IP address")
	}

	baseIP = baseIP.To4()
	if baseIP == nil {
		return nil, fmt.Errorf("only IPv4 addresses are supported")
	}

	endNum, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("invalid end number in range: %w", err)
	}

	if endNum < 0 || endNum > 255 {
		return nil, fmt.Errorf("end number must be between 0 and 255")
	}

	var ips []string
	baseNum := int(baseIP[3])
	if endNum < baseNum {
		return nil, fmt.Errorf("end number must be greater than or equal to the last octet of the base IP")
	}

	for i := baseNum; i <= endNum; i++ {
		ip := make(net.IP, len(baseIP))
		copy(ip, baseIP)
		ip[3] = byte(i)
		ips = append(ips, ip.String())
	}

	return ips, nil
}

// inc increments an IP address
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
