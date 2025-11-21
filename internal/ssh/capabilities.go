package ssh

import (
	"context"
	"sync"
	"time"
)

type Capabilities struct {
	SudoNoPass   bool
	RequireTTY   bool
	IptablesPath string
	DetectedAt   time.Time
}

type CapCache struct {
	mu    sync.RWMutex
	items map[string]Capabilities // key=host.IP or host.ID
	ttl   time.Duration
}

func NewCapCache(ttl time.Duration) *CapCache {
	return &CapCache{
		items: make(map[string]Capabilities),
		ttl:   ttl,
	}
}

func (cc *CapCache) Get(key string) (Capabilities, bool) {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	cap, ok := cc.items[key]
	if !ok {
		return Capabilities{}, false
	}
	if cc.ttl > 0 && time.Since(cap.DetectedAt) > cc.ttl {
		return Capabilities{}, false
	}
	return cap, true
}

func (cc *CapCache) Set(key string, cap Capabilities) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cap.DetectedAt = time.Now()
	cc.items[key] = cap
}

// ProbeCapabilities：首次连接后探测 sudo/iptables 路径等
func (c *Client) ProbeCapabilities(ctx context.Context) Capabilities {
	key := c.cacheKey()
	if c.CapCache != nil {
		if cap, ok := c.CapCache.Get(key); ok {
			return cap
		}
	}

	cap := Capabilities{
		IptablesPath: "/usr/sbin/iptables",
	}

	// 探测 sudo -n 是否可用
	r := c.Exec(ctx, "sudo -n true", WithShell(true), WithTimeout(5*time.Second))
	if r.Err == nil {
		cap.SudoNoPass = true
	} else {
		cap.SudoNoPass = false
		if looksLikeRequireTTY(r.Stderr) {
			cap.RequireTTY = true
		}
	}

	// 探测 iptables 路径（允许不同发行版）
	r2 := c.Exec(ctx, "command -v iptables || which iptables", WithShell(true), WithTimeout(5*time.Second))
	if r2.Err == nil {
		p := trim1stLine(r2.Stdout)
		if p != "" {
			cap.IptablesPath = p
		}
	}

	if c.CapCache != nil {
		c.CapCache.Set(key, cap)
	}
	return cap
}
