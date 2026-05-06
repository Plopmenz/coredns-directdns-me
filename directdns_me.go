package directdns_me

import (
    "context"
    "fmt"
    "net"
    "strings"

    "github.com/coredns/coredns/plugin"
    "github.com/coredns/coredns/plugin/pkg/log"
    "github.com/coredns/coredns/request"
    "github.com/miekg/dns"
)

func getPublicAddresses(qtype string) []net.IP {
    var ips []net.IP

    interfaces, err := net.Interfaces()
    if err != nil {
        return ips
    }

    for _, iface := range interfaces {
        // Skip loopback and ygg0
        if iface.Name == "lo" || iface.Name == "ygg0" {
            continue
        }

        addrs, err := iface.Addrs()
        if err != nil {
            continue
        }

        for _, addr := range addrs {
            ipNet, ok := addr.(*net.IPNet)
            if !ok {
                continue
            }

            ip := ipNet.IP

            // Exclude non-public addresses
            if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
               ip.IsPrivate() || ip.IsMulticast() || !ip.IsGlobalUnicast() {
                continue
            }

            // Exclude unspecified address (0.0.0.0 or ::)
            if ip.IsUnspecified() {
                continue
            }

            if qtype == "A" && ip.To4() != nil {
                ips = append(ips, ip)
            } else if qtype == "AAAA" && ip.To4() == nil && ip.To16() != nil {
                ips = append(ips, ip)
            }
        }
    }

    return ips
}

type DirectDNSMe struct {
    Next plugin.Handler
    Zones []string
}

func (d *DirectDNSMe) Name() string {
    return "directdns_me"
}

func (d *DirectDNSMe) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
    state := request.Request{W: w, Req: r}
    qname := state.Name()
    qtype := state.Type()
    log.Debugf("[directdns_me] ENTRY qname=%s qtype=%d", qname, qtype)

    // Pass through non-matching zones
    zone := d.matchZone(qname)
    log.Debugf("[directdns_me] MATCHED zone=%s from zones=%s", zone, d.Zones)
    if zone == "" {
        log.Debugf("[directdns_me] PASSING to next plugin")
        return plugin.NextOrFailure(d.Name(), d.Next, ctx, w, r)
    }

    // Extract prefix (part before our zone)
    prefix := strings.TrimSuffix(qname, zone)
    prefix = strings.TrimSuffix(prefix, ".")
    log.Debugf("[directdns_me] prefix=%s", prefix)

    // Get self info on demand (no caching)
    self, err := getSelf()
    if err != nil {
        log.Debugf("[directdns_me] getself failed: %v", err)
        return dns.RcodeServerFailure, err
    }
    ipv6 := self.Address
    ipv6Enc := strings.ReplaceAll(ipv6, ":", "-")
    log.Debugf("[directdns_me] ipv6=%s ipv6Enc=%s", ipv6, ipv6Enc)

    // Case 1: AAAA query for <ipv6-enc>.<zone>
    if prefix == ipv6Enc {
        if qtype == "AAAA" {
            ip := net.ParseIP(ipv6)
            if ip == nil {
                log.Debugf("[directdns_me] invalid IPv6 address: %s", ipv6)
                return dns.RcodeServerFailure, nil
            }

            msg := new(dns.Msg)
            msg.SetReply(r)
            msg.Authoritative = true
            msg.Answer = []dns.RR{
                &dns.AAAA{
                    Hdr: dns.RR_Header{
                        Name:   qname,
                        Rrtype: dns.TypeAAAA,
                        Class:  dns.ClassINET,
                        Ttl:    60,
                    },
                    AAAA: ip,
                },
            }
            w.WriteMsg(msg)
            return dns.RcodeSuccess, nil
        }
        // Name exists but no record of requested type
        msg := new(dns.Msg)
        msg.SetReply(r)
        msg.Authoritative = true
        w.WriteMsg(msg)
        return dns.RcodeSuccess, nil
    }

    // Case 2: CNAME record at _public_dns.<ipv6-enc>.<zone>
    if prefix == "_public_dns."+ipv6Enc {
        // Early termination: check for public addresses on network interfaces
        publicIPs := getPublicAddresses(qtype)
        if len(publicIPs) > 0 {
            log.Debugf("[directdns_me] found %d public IPs, responding directly", len(publicIPs))
            msg := new(dns.Msg)
            msg.SetReply(r)
            msg.Authoritative = true

            for _, ip := range publicIPs {
                if qtype == "A" {
                    msg.Answer = append(msg.Answer, &dns.A{
                        Hdr: dns.RR_Header{
                            Name:   qname,
                            Rrtype: dns.TypeA,
                            Class:  dns.ClassINET,
                            Ttl:    60,
                        },
                        A: ip,
                    })
                } else if qtype == "AAAA" {
                    msg.Answer = append(msg.Answer, &dns.AAAA{
                        Hdr: dns.RR_Header{
                            Name:   qname,
                            Rrtype: dns.TypeAAAA,
                            Class:  dns.ClassINET,
                            Ttl:    60,
                        },
                        AAAA: ip,
                    })
                }
            }

            w.WriteMsg(msg)
            return dns.RcodeSuccess, nil
        }

        // Fall back to DNS query via peer
        peers, err := getPeers()
        if err != nil {
            log.Debugf("[directdns_me] getPeers failed: %v", err)
            return dns.RcodeServerFailure, err
        }
        if len(peers.Peers) == 0 {
            msg := new(dns.Msg)
            msg.SetReply(r)
            msg.Authoritative = true
            w.WriteMsg(msg)
            return dns.RcodeSuccess, nil
        }
        firstPeer := peers.Peers[0]

        peerIPv6 := firstPeer.Address
        peerIPv6Enc := strings.ReplaceAll(peerIPv6, ":", "-")
        cnameTarget := fmt.Sprintf("_public_dns.%s.%s", peerIPv6Enc, zone)

        msg := new(dns.Msg)
        msg.SetReply(r)
        msg.Authoritative = true

        // Add CNAME record pointing to the peer's DNS name
        cname := &dns.CNAME{
            Hdr: dns.RR_Header{
                Name:   qname,
                Rrtype: dns.TypeCNAME,
                Class:  dns.ClassINET,
                Ttl:    60,
            },
            Target: cnameTarget,
        }
        msg.Answer = append(msg.Answer, cname)

        w.WriteMsg(msg)
        return dns.RcodeSuccess, nil
    }

    // No matching subdomain pattern - pass to next plugin
    return plugin.NextOrFailure(d.Name(), d.Next, ctx, w, r)
}

func (d *DirectDNSMe) matchZone(qname string) string {
    for _, zone := range d.Zones {
        if plugin.Name(zone).Matches(qname) {
            return zone
        }
    }
    return ""
}
