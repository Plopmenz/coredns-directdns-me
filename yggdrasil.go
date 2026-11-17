package directdns_me

import (
    "context"
    "encoding/json"
    "fmt"
    "os/exec"
    "sync"
    "time"
)

const (
    selfCacheTTL  = 1 * time.Minute
    peersCacheTTL = 5 * time.Second
)

type cacheEntry[T any] struct {
    value   T
    expires time.Time
}

var (
    selfCache  cacheEntry[*SelfInfo]
    selfMu     sync.Mutex
    peersCache cacheEntry[*PeersResponse]
    peersMu    sync.Mutex
)

type SelfInfo struct {
    Address string `json:"address"`
}

type Peer struct {
    Key     string `json:"key"`
    Address     string `json:"address"`
    Remote string `json:"remote"`
    Cost    int    `json:"cost"`
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
    selfMu.Lock()
    defer selfMu.Unlock()

    if selfCache.value != nil && time.Now().Before(selfCache.expires) {
        return selfCache.value, nil
    }

    out, err := runYggdrasil("-json", "getself")
    if err != nil {
        return nil, fmt.Errorf("yggdrasilctl getself: %w", err)
    }

    var info SelfInfo
    if err := json.Unmarshal(out, &info); err != nil {
        return nil, fmt.Errorf("parse getself: %w", err)
    }
    selfCache = cacheEntry[*SelfInfo]{value: &info, expires: time.Now().Add(selfCacheTTL)}
    return &info, nil
}

func getPeers() (*PeersResponse, error) {
    peersMu.Lock()
    defer peersMu.Unlock()

    if peersCache.value != nil && time.Now().Before(peersCache.expires) {
        return peersCache.value, nil
    }

    out, err := runYggdrasil("-json", "getPeers")
    if err != nil {
        return nil, fmt.Errorf("yggdrasilctl getPeers: %w", err)
    }

    var resp PeersResponse
    if err := json.Unmarshal(out, &resp); err != nil {
        return nil, fmt.Errorf("parse getPeers: %w", err)
    }
    peersCache = cacheEntry[*PeersResponse]{value: &resp, expires: time.Now().Add(peersCacheTTL)}
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
