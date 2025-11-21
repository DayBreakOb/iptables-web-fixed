package ssh

import (
	"context"
)

func (c *Client) Exec(ctx context.Context, raw string, opts ...ExecOption) Result {
	cmd := buildCommand(raw, opts...)

	// 超时
	to := defaultTimeout(c, cmd)
	if to > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, to)
		defer cancel()
	}

	strategy := StrategyByHost(c)
	res := strategy.Exec(ctx, c, cmd)
	res.HostIP = c.Host.IP
	res.Strategy = strategy.Name()

	if c.Hooks.OnResult != nil {
		c.Hooks.OnResult(c.Host, cmd, res)
	}

	return res
}

// 兼容你旧风格：Exec(cmd, needsPTY, stdin)
func (c *Client) ExecCompat(cmd string, needsPTY bool, stdin string) (string, string, error) {
	res := c.Exec(context.Background(), cmd, WithPTY(needsPTY), WithStdin(stdin), WithShell(true))
	return res.Stdout, res.Stderr, res.Err
}
