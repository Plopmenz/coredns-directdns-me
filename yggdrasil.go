package directdns_me

import (
    "encoding/json"
    "fmt"
    "os/exec"
)

type SelfInfo struct {
    Address string `json:"address"`
}

type Peer struct {
    Key  string `json:"key"`
    Port int    `json:"port"`
}

type PeersResponse struct {
    Peers []Peer `json:"peers"`
}

type NodeInfo map[string]interface{}

func getSelf() (*SelfInfo, error) {
    cmd := exec.Command("yggdrasilctl", "-json", "getself")
    out, err := cmd.Output()
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
    cmd := exec.Command("yggdrasilctl", "-json", "getPeers")
    out, err := cmd.Output()
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
    cmd := exec.Command("yggdrasilctl", "-json", fmt.Sprintf("getnodeinfo key=%s", key))
    out, err := cmd.Output()
    if err != nil {
        return nil, fmt.Errorf("yggdrasilctl getnodeinfo: %w", err)
    }

    var info NodeInfo
    if err := json.Unmarshal(out, &info); err != nil {
        return nil, fmt.Errorf("parse getnodeinfo: %w", err)
    }
    return info, nil
}
