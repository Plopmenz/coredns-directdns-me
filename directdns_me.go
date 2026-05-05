package directdns_me

import (
    "context"
    "log"
    "net"
    "strings"

    "github.com/coredns/coredns/plugin"
    "github.com/miekg/dns"
)

type DirectDNSMe struct {
    next plugin.Handler
    zone string
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

    // Normalize zone to have trailing dot
    zone := d.zone
    if !strings.HasSuffix(zone, ".") {
        zone = zone + "."
    }

    // Pass through non-matching zones
    if !strings.HasSuffix(qname, zone) {
        return plugin.NextOrFailure(d.Name(), d.next, ctx, w, r)
    }

    // Extract prefix (part before our zone)
    prefix := strings.TrimSuffix(qname, zone)
    prefix = strings.TrimSuffix(prefix, ".")

    // Get self info on demand (no caching)
    self, err := getSelf()
    if err != nil {
        log.Printf("[directdns_me] getself failed: %v", err)
        return dns.RcodeServerFailure, err
    }
    ipv6 := self.Address
    ipv6Enc := strings.ReplaceAll(ipv6, ":", "-")

    // Case 1: AAAA query for <ipv6-enc>.<zone>
    if prefix == ipv6Enc {
        if qtype == dns.TypeAAAA {
            ip := net.ParseIP(ipv6)
            if ip == nil {
                log.Printf("[directdns_me] invalid IPv6 address: %s", ipv6)
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
            log.Printf("[directdns_me] getPeers failed: %v", err)
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

        nodeInfo, err := getNodeInfo(firstPeer.Key)
        if err != nil {
            log.Printf("[directdns_me] getNodeInfo failed for peer %s: %v", firstPeer.Key, err)
            return dns.RcodeServerFailure, err
        }

        infoVal, exists := nodeInfo[firstPeer.Key]
        if !exists {
            log.Printf("[directdns_me] no node info for key %s", firstPeer.Key)
            msg := new(dns.Msg)
            msg.SetReply(r)
            msg.Authoritative = true
            w.WriteMsg(msg)
            return dns.RcodeSuccess, nil
        }
        infoMap, ok := infoVal.(map[string]interface{})
        if !ok {
            log.Printf("[directdns_me] invalid node info format for key %s", firstPeer.Key)
            msg := new(dns.Msg)
            msg.SetReply(r)
            msg.Authoritative = true
            w.WriteMsg(msg)
            return dns.RcodeSuccess, nil
        }
        publicDNS, ok := infoMap["_public_dns"].(string)
        if !ok {
            log.Printf("[directdns_me] no _public_dns for peer %s", firstPeer.Key)
            msg := new(dns.Msg)
            msg.SetReply(r)
            msg.Authoritative = true
            w.WriteMsg(msg)
            return dns.RcodeSuccess, nil
        }

        cnameTarget := publicDNS
        if !strings.HasSuffix(cnameTarget, ".") {
            cnameTarget += "."
        }
        msg := new(dns.Msg)
        msg.SetReply(r)
        msg.Authoritative = true
        msg.Answer = []dns.RR{
            &dns.CNAME{
                Hdr: dns.RR_Header{
                    Name:   qname,
                    Rrtype: dns.TypeCNAME,
                    Class:  dns.ClassINET,
                    Ttl:    60,
                },
                Target: cnameTarget,
            },
        }
        w.WriteMsg(msg)
        return dns.RcodeSuccess, nil
    }

    // No matching subdomain pattern - pass to next plugin
    return plugin.NextOrFailure(d.Name(), d.next, ctx, w, r)
}
