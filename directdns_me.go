package directdns_me

import (
    "context"
    "fmt"
    "net"
    "net/netip"
    "sort"
    "strings"

    "github.com/coredns/coredns/plugin"
    "github.com/coredns/coredns/plugin/pkg/log"
    "github.com/coredns/coredns/plugin/pkg/upstream"
    "github.com/coredns/coredns/request"
    "github.com/miekg/dns"
)

type PublicAddress struct {
    IP  net.IP
    TTL uint32
}

func getPublicAddresses(qtype string) []PublicAddress {
    var addresses []PublicAddress
    dhcpLft := dhcpLifetimes()

    interfaces, err := net.Interfaces()
    if err != nil {
        return addresses
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
                addresses = append(addresses, PublicAddress{IP: ip, TTL: publicAddressTTL(ip, dhcpLft)})
            } else if qtype == "AAAA" && ip.To4() == nil && ip.To16() != nil {
                addresses = append(addresses, PublicAddress{IP: ip, TTL: publicAddressTTL(ip, dhcpLft)})
            }
        }
    }

    return addresses
}

type DirectDNSMe struct {
    Next     plugin.Handler
    Zones    []string
    upstream *upstream.Upstream
}

func (d *DirectDNSMe) Name() string {
    return "directdns_me"
}

func parseAddrLabel(label string) (netip.Addr, error) {
    if label == "" {
        return netip.Addr{}, fmt.Errorf("empty label")
    }
    if strings.ContainsAny(label, ":%.") {
        return netip.Addr{}, fmt.Errorf("invalid characters in label %q", label)
    }
    addr, err := netip.ParseAddr(strings.ReplaceAll(label, "-", ":"))
    if err != nil {
        return netip.Addr{}, err
    }
    if !addr.Is6() || addr.Is4In6() || addr.Zone() != "" {
        return netip.Addr{}, fmt.Errorf("not a plain IPv6 address: %q", label)
    }
    return addr, nil
}

func (d *DirectDNSMe) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
    state := request.Request{W: w, Req: r}
    qname := state.Name()
    qtype := state.Type()
    log.Debugf("[directdns_me] ENTRY qname=%s qtype=%s", qname, qtype)

    // Pass through non-matching zones
    zone := d.matchZone(qname)
    log.Debugf("[directdns_me] MATCHED zone=%s from zones=%s", zone, d.Zones)
    if zone == "" {
        log.Debugf("[directdns_me] PASSING to next plugin")
        return plugin.NextOrFailure(d.Name(), d.Next, ctx, w, r)
    }

    // Split the part before our zone into <prefix><addr-label>, where prefix is
    // everything up to and including the last dot (empty if there is none).
    rest := strings.TrimSuffix(qname, zone)
    rest = strings.TrimSuffix(rest, ".")
    prefix, addrLabel := "", rest
    if i := strings.LastIndex(rest, "."); i >= 0 {
        prefix, addrLabel = rest[:i+1], rest[i+1:]
    }
    log.Debugf("[directdns_me] prefix=%q addrLabel=%q", prefix, addrLabel)

    reqAddr, err := parseAddrLabel(addrLabel)
    if err != nil {
        log.Debugf("[directdns_me] could not parse request address label %q: %v", addrLabel, err)
        return plugin.NextOrFailure(d.Name(), d.Next, ctx, w, r)
    }

    // Get self info on demand (no caching)
    self, err := getSelf()
    if err != nil {
        log.Debugf("[directdns_me] getself failed: %v", err)
        return dns.RcodeServerFailure, err
    }
    myAddr, err := netip.ParseAddr(self.Address)
    if err != nil {
        log.Debugf("[directdns_me] invalid self address %q: %v", self.Address, err)
        return dns.RcodeServerFailure, err
    }
    log.Debugf("[directdns_me] myAddr=%s reqAddr=%s", myAddr, reqAddr)

    if reqAddr == myAddr {
        msg := new(dns.Msg)
        msg.SetReply(r)
        msg.Authoritative = true
                
        // Case 1: AAAA query for <ipv6-enc>.<zone>
        if prefix == "" {
            if qtype == "AAAA" {
                msg.Answer = []dns.RR{
                    &dns.AAAA{
                        Hdr: dns.RR_Header{
                            Name:   qname,
                            Rrtype: dns.TypeAAAA,
                            Class:  dns.ClassINET,
                            Ttl:    24 * 60 * 60,
                        },
                        AAAA: myAddr.AsSlice(),
                    },
                }
                w.WriteMsg(msg)
                return dns.RcodeSuccess, nil
            }
        }

        // Case 2: CNAME record at public.directdns.<ipv6-enc>.<zone>
        if prefix == "public.directdns." {
            if qtype == "A" || qtype == "AAAA" {
                // Early termination: check for public addresses on network interfaces
                publicIPs := getPublicAddresses(qtype)
                if len(publicIPs) > 0 {
                    log.Debugf("[directdns_me] found %d public IPs, responding directly", len(publicIPs))

                    for _, publicIP := range publicIPs {
                        log.Debugf("[directdns_me] serving %s %s with TTL %d", qtype, publicIP.IP, publicIP.TTL)
                        if qtype == "A" {
                            msg.Answer = append(msg.Answer, &dns.A{
                                Hdr: dns.RR_Header{
                                    Name:   qname,
                                    Rrtype: dns.TypeA,
                                    Class:  dns.ClassINET,
                                    Ttl:    publicIP.TTL,
                                },
                                A: publicIP.IP,
                            })
                        } else if qtype == "AAAA" {
                            msg.Answer = append(msg.Answer, &dns.AAAA{
                                Hdr: dns.RR_Header{
                                    Name:   qname,
                                    Rrtype: dns.TypeAAAA,
                                    Class:  dns.ClassINET,
                                    Ttl:    publicIP.TTL,
                                },
                                AAAA: publicIP.IP,
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
                // Sort peers by local last, then lowest cost
                sort.Slice(peers.Peers, func(i, j int) bool {
                    iIsLocal := strings.Contains(peers.Peers[i].Remote, "%") || strings.Contains(peers.Peers[i].Remote, "127.0.0.1")
                    jIsLocal := strings.Contains(peers.Peers[j].Remote, "%") || strings.Contains(peers.Peers[j].Remote, "127.0.0.1")
                    if iIsLocal != jIsLocal {
                        return !iIsLocal
                    }
                    return peers.Peers[i].Cost < peers.Peers[j].Cost
                })
                peer := peers.Peers[0]

                peerIPv6 := peer.Address
                peerIPv6Enc := strings.ReplaceAll(peerIPv6, ":", "-")
                cnameTarget := fmt.Sprintf("public.directdns.%s.%s", peerIPv6Enc, zone)

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

                // Resolve the CNAME target via the local CoreDNS chain
                log.Debugf("[directdns_me] resolving CNAME target %s via local chain", cname.Target)
                ipv6Resp, err := d.upstream.Lookup(ctx, state, cname.Target, state.QType())
                if err != nil {
                    log.Debugf("[directdns_me] local chain lookup failed: %v", err)
                }
                if ipv6Resp != nil && len(ipv6Resp.Answer) > 0 {
                    msg.Answer = append(msg.Answer, ipv6Resp.Answer...)
                }

                w.WriteMsg(msg)
                return dns.RcodeSuccess, nil
            }
        }

        // Case 3: no records for the requested type or any other prefix of <ipv6-enc>.<zone>
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