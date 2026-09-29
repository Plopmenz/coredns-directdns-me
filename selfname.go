package directdns_me

import (
	"net"
	"strings"
)

// isSelfLabel reports whether an encoded label names this node's address.
// It compares addresses, not text: "0609" and "609" are the same group, and a
// query spelled either way must be answered here rather than passed on.
func isSelfLabel(label string, self net.IP) bool {
	ip := net.ParseIP(strings.ReplaceAll(label, "-", ":"))
	return ip != nil && self != nil && ip.Equal(self)
}
