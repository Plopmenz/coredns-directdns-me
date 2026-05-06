package directdns_me

import (
    "context"
    "encoding/json"
    "fmt"
    "os/exec"
    "time"

    "github.com/miekg/dns"
)

type SelfInfo struct {
    Address string `json:"address"`
}

type Peer struct {
    Key     string `json:"key"`
    Port    int    `json:"port"`
    Address string `json:"address"`
}

type PeersResponse struct {
    Peers []Peer `json:"peers"`
}

type NodeInfo map[string]interface{}

func runYggdrasil(args ...string) ([]byte, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    cmd := exec.CommandContext(ctx, "yggdrasilctl", args...)
    return cmd.Output()
}

func getSelf() (*SelfInfo, error) {
    out, err := runYggdrasil("-json", "getself")
    if err != nil {
        return nil, fmt.Errorf("yggdrasilctl getself: %w", err)
    }

    var info SelfInfo
    if err := json.Unmarshal(out, &info); err != nil {
        return nil, fmt.Errorf("parse getself: %w", err)
    }
    return &info, nil
}

func getPeers() (*PeersResponse, error) {
    out, err := runYggdrasil("-json", "getPeers")
    if err != nil {
        return nil, fmt.Errorf("yggdrasilctl getPeers: %w", err)
    }

    var resp PeersResponse
    if err := json.Unmarshal(out, &resp); err != nil {
        return nil, fmt.Errorf("parse getPeers: %w", err)
    }
    return &resp, nil
}

func getNodeInfo(key string) (NodeInfo, error) {
    out, err := runYggdrasil("-json", "getnodeinfo", fmt.Sprintf("key=%s", key))
    if err != nil {
        return nil, fmt.Errorf("yggdrasilctl getnodeinfo: %w", err)
    }

    var info NodeInfo
    if err := json.Unmarshal(out, &info); err != nil {
        return nil, fmt.Errorf("parse getnodeinfo: %w", err)
    }
    return info, nil
}

func queryDNS(name string, qtype uint16, peerIPv6 ...string) ([]dns.RR, error) {
    c := new(dns.Client)
    m := new(dns.Msg)
    m.SetQuestion(name, qtype)
    m.RecursionDesired = true

    // Try localhost first, then try using the yggdrasil network via the peer
    servers := []string{"127.0.0.1:53", "[::1]:53"}
    for _, ipv6 := range peerIPv6 {
        servers = append(servers, fmt.Sprintf("[%s]:53", ipv6))
    }
    var lastErr error

    for _, server := range servers {
        resp, _, err := c.Exchange(m, server)
        if err != nil {
            lastErr = err
            continue
        }
        if resp.Rcode != dns.RcodeSuccess {
            lastErr = fmt.Errorf("DNS query failed with rcode %d", resp.Rcode)
            continue
        }
        return resp.Answer, nil
    }
    return nil, lastErr
}
