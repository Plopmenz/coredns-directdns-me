package directdns_me

import (
    "context"
    "fmt"
    "net"
    "strings"

    "github.com/coredns/coredns/plugin"
    "github.com/coredns/coredns/plugin/pkg/log"
    "github.com/miekg/dns"
)

type DirectDNSMe struct {
    Next plugin.Handler
    Zones []string
}

func (d *DirectDNSMe) Name() string {
    return "directdns_me"
}

func (d *DirectDNSMe) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
    if len(r.Question) == 0 {
        return dns.RcodeFormatError, nil
    }

    q := r.Question[0]
    qname := q.Name
    qtype := q.Qtype
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
        if qtype == dns.TypeAAAA {
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
        dnsQueryName := fmt.Sprintf("_public_dns.%s.yggdrasil.trustless.cloud.", peerIPv6Enc)
        cnameTarget := dnsQueryName

        log.Debugf("[directdns_me] querying DNS for %s using peer %s", dnsQueryName, peerIPv6)

        // Query the DNS name using localhost resolver or peer's IPv6
        dnsResults, err := queryDNS(dnsQueryName, qtype, peerIPv6)
        if err != nil {
            log.Debugf("[directdns_me] DNS query failed for %s: %v", dnsQueryName, err)
        }

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

        // Add the DNS query results
        if dnsResults != nil {
            msg.Answer = append(msg.Answer, dnsResults...)
        }

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
