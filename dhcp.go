package directdns_me

import (
    "net"

    "github.com/vishvananda/netlink"
)

const (
    // defaultPublicIPTTL is the TTL, in seconds, applied to public addresses
    // that are not backed by a DHCP lease (e.g. statically configured).
    defaultPublicIPTTL = 24 * 60 * 60

    // minPublicIPTTL is the floor for TTLs derived from DHCP leases, so a
    // record is not published with a near-zero TTL right before expiry.
    minPublicIPTTL = 60

    // infiniteLifetime is the kernel's valid_lft for permanent addresses.
    infiniteLifetime = 0xFFFFFFFF
)

// publicAddressTTL returns the TTL to serve for ip. Addresses with a finite
// kernel lifetime (kept in sync with the remaining DHCP lease duration by
// systemd-networkd) use that remaining time; everything else falls back to
// defaultPublicIPTTL.
func publicAddressTTL(ip net.IP, dhcpLifetimes map[string]int) uint32 {
    if lft, ok := dhcpLifetimes[ip.String()]; ok && lft > 0 {
        if lft < minPublicIPTTL {
            return minPublicIPTTL
        }
        return uint32(lft)
    }
    return defaultPublicIPTTL
}

// dhcpLifetimes maps each dynamically assigned address to its remaining valid
// lifetime in seconds. It walks all interfaces and keeps only addresses with a
// finite kernel lifetime; statically configured addresses carry an infinite
// valid_lft and are excluded so their records use the default TTL.
func dhcpLifetimes() map[string]int {
    lifetimes := make(map[string]int)

    links, err := netlink.LinkList()
    if err != nil {
        return lifetimes
    }

    for _, link := range links {
        name := link.Attrs().Name
        if name == "lo" || name == "ygg0" {
            continue
        }

        addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
        if err != nil {
            continue
        }

        for _, addr := range addrs {
            if addr.ValidLft > 0 && uint64(addr.ValidLft) < infiniteLifetime {
                lifetimes[addr.IP.String()] = addr.ValidLft
            }
        }
    }

    return lifetimes
}
