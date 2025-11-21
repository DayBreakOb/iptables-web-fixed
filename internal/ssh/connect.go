package ssh

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"iptables-web/backend/internal/models"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/sync/singleflight"
)

type Client struct {
	Host models.Host

	AuthProviders []AuthProvider // P3：认证插件链
	CapCache      *CapCache

	// 连接复用
	mu   sync.Mutex
	cli  *gossh.Client
	user string
	pass string

	lastUse time.Time
	sf      singleflight.Group

	// 默认超时配置
	DialTimeout time.Duration
	CmdTimeout  time.Duration
	KeepAlive   time.Duration

	// 审计/指标 hook（P2）
	Hooks Hooks
}

type Hooks struct {
	OnConnect func(host models.Host, user string, err error)
	OnResult  func(host models.Host, cmd Command, res Result)
	OnTask    func(task Task) // 任务状态变更
}

func New(h models.Host) *Client {
	return &Client{
		Host:        h,
		DialTimeout: 10 * time.Second,
		CmdTimeout:  30 * time.Second,
		KeepAlive:   30 * time.Second,
		AuthProviders: []AuthProvider{
			PasswordAuth{}, // 默认密码
		},
	}
}

// getOrConnect：并发安全单飞行连接
func (c *Client) getOrConnect() (*gossh.Client, string, error) {
	c.mu.Lock()
	if c.cli != nil && time.Since(c.lastUse) < 5*time.Minute {
		c.lastUse = time.Now()
		cli := c.cli
		user := c.user
		c.mu.Unlock()
		return cli, user, nil
	}
	c.mu.Unlock()

	v, err, _ := c.sf.Do("connect", func() (interface{}, error) {
		return c.connectFresh()
	})
	if err != nil {
		return nil, "", err
	}
	out := v.(struct {
		cli  *gossh.Client
		user string
	})
	return out.cli, out.user, nil
}

func (c *Client) connectFresh() (struct {
	cli  *gossh.Client
	user string
}, error) {
	addr := fmt.Sprintf("%s:%d", c.Host.IP, portOrDefault(c.Host.Port))
	var lastErr error

	for _, ap := range c.AuthProviders {
		user, methods, err := ap.Methods(c.Host)
		if err != nil {
			lastErr = err
			continue
		}

		conf := &gossh.ClientConfig{
			User:            user,
			Auth:            methods,
			HostKeyCallback: gossh.InsecureIgnoreHostKey(),
			Timeout:         c.DialTimeout,
		}

		log.Printf("[ssh] dial host=%s user=%s auth=%s", addr, user, ap.Name())
		cli, err := gossh.Dial("tcp", addr, conf)
		if err == nil {
			c.mu.Lock()
			if c.cli != nil {
				_ = c.cli.Close()
			}
			c.cli = cli
			c.user = user
			// pass 仅 PasswordAuth 会用到 sudo fallback，继续存（你也可以加密态存）
			if pa, ok := ap.(PasswordAuth); ok {
				_ = pa // placeholder
			}
			c.lastUse = time.Now()
			c.mu.Unlock()

			go c.keepAliveLoop(cli)

			if c.Hooks.OnConnect != nil {
				c.Hooks.OnConnect(c.Host, user, nil)
			}
			return struct {
				cli  *gossh.Client
				user string
			}{cli: cli, user: user}, nil
		}

		lastErr = err
		if isTimeout(err) {
			// 超时直接退出
			break
		}
	}

	if c.Hooks.OnConnect != nil {
		c.Hooks.OnConnect(c.Host, "", lastErr)
	}
	return struct {
		cli  *gossh.Client
		user string
	}{}, fmt.Errorf("dial %s: %w", addr, lastErr)
}

func (c *Client) keepAliveLoop(cli *gossh.Client) {
	if c.KeepAlive <= 0 {
		return
	}
	tk := time.NewTicker(c.KeepAlive)
	defer tk.Stop()
	for range tk.C {
		_, _, err := cli.SendRequest("keepalive@openssh.com", true, nil)
		if err != nil {
			return
		}
	}
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cli != nil {
		err := c.cli.Close()
		c.cli = nil
		return err
	}
	return nil
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return false
}

func (c *Client) cacheKey() string {
	return c.Host.IP
}
