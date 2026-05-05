package directdns_me

import (
    "github.com/coredns/caddy"
    "github.com/coredns/coredns/core/dnsserver"
    "github.com/coredns/coredns/plugin"
    "github.com/coredns/coredns/plugin/pkg/log"
    "github.com/miekg/dns"
)

func init() { plugin.Register("directdns_me", setup) }

func setup(c *caddy.Controller) error {
    d := &DirectDNSMe{}
    for c.Next() {
        args := c.RemainingArgs()
        if len(args) == 0 {
            return c.ArgErr()
        }
        for _, zone := range args {
            normalized := dns.Fqdn(zone)
            log.Debugf("[directdns_me] adding zone: %s (from %s)", normalized, zone)
            d.Zones = append(d.Zones, normalized)
        }
    }

    dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
        d.Next = next
        log.Debugf("[directdns_me] plugin instance created, Next is nil: %v", next == nil)
        return d
    })

    return nil
}
