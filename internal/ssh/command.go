package ssh

import (
	"context"
	"time"
)

type Command struct {
	Raw     string
	Args    []string
	Stdin   string
	PTY     bool
	Shell   bool
	Timeout time.Duration
	Env     map[string]string
	WorkDir string
}

type Result struct {
	HostIP   string
	Stdout   string
	Stderr   string
	Err      error
	Code     int
	Spent    time.Duration
	Strategy string
}

type ExecOption func(*Command)

func WithStdin(s string) ExecOption { return func(c *Command) { c.Stdin = s } }
func WithPTY(v bool) ExecOption     { return func(c *Command) { c.PTY = v } }
func WithShell(v bool) ExecOption   { return func(c *Command) { c.Shell = v } }
func WithTimeout(d time.Duration) ExecOption {
	return func(c *Command) { c.Timeout = d }
}
func WithEnv(k, v string) ExecOption {
	return func(c *Command) {
		if c.Env == nil {
			c.Env = map[string]string{}
		}
		c.Env[k] = v
	}
}
func WithWorkDir(d string) ExecOption { return func(c *Command) { c.WorkDir = d } }

type ExecStrategy interface {
	Exec(ctx context.Context, c *Client, cmd Command) Result
	Name() string
}
