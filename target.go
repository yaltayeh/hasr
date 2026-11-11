package main

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// canonicalTarget returns the one form of a target that every input
// (command line, --targets, mapping CSV, scan JSON) is matched on:
//
//   - port: decimal digits only, 1-65535, written without leading zeros;
//     service names ("https") and empty ports are rejected;
//   - host: lowercased, one trailing dot removed;
//   - IP addresses in their standard form, IPv6 in [brackets].
//
// With defaultPort, a target without a port gets :443 (command line only;
// the mapping CSV needs an explicit port).
func canonicalTarget(s string, defaultPort bool) (string, error) {
	in := strings.TrimSpace(s)
	if in == "" {
		return "", fmt.Errorf("empty target")
	}
	if strings.Contains(in, "://") {
		return "", fmt.Errorf("target %q is a URL; give host:port", in)
	}
	hostport := in
	if defaultPort && !hasPort(in) {
		host := strings.TrimSuffix(strings.TrimPrefix(in, "["), "]")
		hostport = net.JoinHostPort(host, "443")
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		if defaultPort {
			return "", fmt.Errorf("target %q must be host or host:port", in)
		}
		return "", fmt.Errorf("target %q must be host:port", in)
	}
	n, err := parsePort(port)
	if err != nil {
		return "", fmt.Errorf("target %q: %v", in, err)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return net.JoinHostPort(addr.String(), strconv.Itoa(n)), nil
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return "", fmt.Errorf("target %q has no host", in)
	}
	for _, r := range host {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_') {
			return "", fmt.Errorf("target %q: host contains %q; give a hostname or IP address (internationalised names in their xn-- form), not a URL", in, r)
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(n)), nil
}

// hasPort reports whether s ends in a port separator: "host:…" or "[v6]:…".
// A bare IPv6 address ("::1") has no port.
func hasPort(s string) bool {
	if strings.HasPrefix(s, "[") {
		return strings.Contains(s, "]:")
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return false
	}
	return strings.Contains(s, ":")
}

func parsePort(p string) (int, error) {
	if p == "" {
		return 0, fmt.Errorf("empty port")
	}
	for _, r := range p {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("port %q is not a number (service names are not accepted)", p)
		}
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %q is outside 1-65535", p)
	}
	return n, nil
}

// isIP reports whether host (without brackets) is an IP address, including
// IPv6 with a zone ("fe80::1%en0"), which net.ParseIP does not accept.
func isIP(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}
