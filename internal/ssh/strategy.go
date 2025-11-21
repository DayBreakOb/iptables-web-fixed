package ssh

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"iptables-web/backend/internal/crypto"
)

type RootStrategy struct{}

func (s RootStrategy) Name() string { return "root" }
func (s RootStrategy) Exec(ctx context.Context, c *Client, cmd Command) Result {
	cli, _, err := c.getOrConnect()
	if err != nil {
		return Result{HostIP: c.Host.IP, Err: err, Code: -1, Strategy: s.Name()}
	}
	res := c.lowLevelRun(ctx, cli, cmd)
	res.Strategy = s.Name()
	return res
}

type SudoStrategy struct{}

func (s SudoStrategy) Name() string { return "sudo" }
func (s SudoStrategy) Exec(ctx context.Context, c *Client, cmd Command) Result {
	cli, _, err := c.getOrConnect()
	if err != nil {
		return Result{HostIP: c.Host.IP, Err: err, Code: -1, Strategy: s.Name()}
	}

	cap := c.ProbeCapabilities(ctx)

	// 1) sudo -n（如果 cap 说NoPass就优先）
	c1 := cmd
	c1.Raw = "sudo -n " + cmd.Raw
	r1 := c.lowLevelRun(ctx, cli, c1)
	r1.Strategy = s.Name()
	if r1.Err == nil {
		return r1
	}

	// 若cap已知 sudo 无密码且失败，直接返回
	if cap.SudoNoPass && !needsSudoPassword(r1.Stderr) {
		return r1
	}

	if !needsSudoPassword(r1.Stderr) && !looksLikeRequireTTY(r1.Stderr) && !looksLikeSudoReadFromTTY(r1.Stderr) {
		return r1
	}
	log.Printf("[ssh] sudo -n fallback host=%s stderr=%q", c.Host.IP, shortForLog(r1.Stderr))

	// 2) sudo -S
	userPass := crypto.MustOpen(c.Host.Password)
	c2 := cmd
	c2.Raw = "sudo -S -p '' " + cmd.Raw
	if cmd.Stdin != "" {
		c2.Stdin = cmd.Stdin + "\n"
	}
	c2.Stdin += userPass + "\n"

	// 需要TTY就走PTY
	if cmd.PTY || cap.RequireTTY || looksLikeRequireTTY(r1.Stderr) || looksLikeSudoReadFromTTY(r1.Stderr) {
		c2.PTY = true
	}

	r2 := c.lowLevelRun(ctx, cli, c2)
	r2.Strategy = s.Name()
	return r2
}

type UserSuStrategy struct{}

func (s UserSuStrategy) Name() string { return "user-su" }
func (s UserSuStrategy) Exec(ctx context.Context, c *Client, cmd Command) Result {
	cli, _, err := c.getOrConnect()
	if err != nil {
		return Result{HostIP: c.Host.IP, Err: err, Code: -1, Strategy: s.Name()}
	}

	rootUser := firstNonEmpty(c.Host.RootUser, "root")
	rootPass := crypto.MustOpen(c.Host.RootPass)

	w := cmd
	w.PTY = true // su 基本需要PTY
	raw := cmd.Raw
	if cmd.Shell {
		raw = pathWrap(raw)
	}
	w.Raw = fmt.Sprintf(`su - %s -c %q`, rootUser, raw)
	if cmd.Stdin != "" {
		w.Stdin = cmd.Stdin + "\n"
	}
	w.Stdin += rootPass + "\n"

	res := c.lowLevelRun(ctx, cli, w)
	res.Strategy = s.Name()
	return res
}

func StrategyByHost(c *Client) ExecStrategy {
	switch normalize(c.Host.LoginMethod) {
	case "root":
		return RootStrategy{}
	case "sudo":
		return SudoStrategy{}
	case "user":
		return UserSuStrategy{}
	default:
		return SudoStrategy{}
	}
}

func normalize(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// 支持未来：允许外部强制策略
type ForcedStrategy struct{ Inner ExecStrategy }

func (s ForcedStrategy) Name() string { return "forced:" + s.Inner.Name() }
func (s ForcedStrategy) Exec(ctx context.Context, c *Client, cmd Command) Result {
	res := s.Inner.Exec(ctx, c, cmd)
	res.Strategy = s.Name()
	return res
}

func defaultTimeout(c *Client, cmd Command) time.Duration {
	if cmd.Timeout > 0 {
		return cmd.Timeout
	}
	return c.CmdTimeout
}
