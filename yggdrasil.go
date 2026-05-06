package directdns_me

import (
    "context"
    "encoding/json"
    "fmt"
    "os/exec"
    "time"
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
