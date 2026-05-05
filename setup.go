package directdns_me

import (
    "github.com/coredns/coredns/core/dnsserver"
    "github.com/coredns/coredns/plugin"
    caddy "github.com/coredns/caddy"
)

func init() {
    caddy.RegisterPlugin("directdns_me", caddy.Plugin{
        ServerType: "dns",
        Action:     setup,
    })
}

func setup(c *caddy.Controller) error {
    if !c.NextArg() {
        return c.ArgErr()
    }
    zone := c.Val()

    d := &DirectDNSMe{
        zone: zone,
    }

    c.OnFinalShutdown(func() error {
        return nil
    })

    dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
        d.next = next
        return d
    })

    return nil
}
