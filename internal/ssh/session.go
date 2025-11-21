package ssh

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// lowLevelRun：纯执行（无提权），支持 ctx 超时
func (c *Client) lowLevelRun(ctx context.Context, cli *gossh.Client, cmd Command) Result {
	start := time.Now()
	s, err := cli.NewSession()
	if err != nil {
		// 可能连接断了 -> 强制重连一次
		_ = c.Close()
		cli2, _, e2 := c.getOrConnect()
		if e2 == nil {
			s, err = cli2.NewSession()
		}
		if err != nil {
			return Result{HostIP: c.Host.IP, Err: err, Code: -1}
		}
	}
	defer s.Close()

	var out, errb bytes.Buffer
	s.Stdout = &out
	s.Stderr = &errb

	runCmd := cmd.Raw
	if cmd.Shell {
		runCmd = pathWrap(runCmd)
	}
	if cmd.WorkDir != "" {
		runCmd = fmt.Sprintf("cd %s && %s", shellEscape(cmd.WorkDir), runCmd)
	}
	if len(cmd.Env) > 0 {
		runCmd = envWrap(cmd.Env, runCmd)
	}

	if cmd.Stdin != "" && !cmd.PTY {
		s.Stdin = strings.NewReader(cmd.Stdin)
	}

	// PTY
	if cmd.PTY {
		if err := s.RequestPty("xterm", 120, 32, gossh.TerminalModes{gossh.ECHO: 0}); err != nil {
			return Result{HostIP: c.Host.IP, Err: fmt.Errorf("request pty: %w", err), Code: -1}
		}
		in, _ := s.StdinPipe()
		if cmd.Stdin != "" {
			go func() {
				time.Sleep(150 * time.Millisecond)
				_, _ = io.WriteString(in, cmd.Stdin)
				_ = in.Close()
			}()
		}
	}

	log.Printf("[ssh] run host=%s pty=%v shell=%v cmd=%q", c.Host.IP, cmd.PTY, cmd.Shell, shortForLog(runCmd))

	done := make(chan error, 1)
	go func() { done <- s.Run(runCmd) }()

	var e error
	select {
	case <-ctx.Done():
		_ = s.Signal(gossh.SIGKILL)
		e = ctx.Err()
	case e = <-done:
	}

	res := Result{
		HostIP: c.Host.IP,
		Stdout: out.String(),
		Stderr: errb.String(),
		Err:    e,
		Code:   exitCode(e),
		Spent:  time.Since(start),
	}
	return res
}

// ExecStream：流式输出（P4）
func (c *Client) ExecStream(
	ctx context.Context,
	raw string,
	onStdout func(line string),
	onStderr func(line string),
	opts ...ExecOption,
) Result {
	cmd := buildCommand(raw, opts...)
	cli, _, err := c.getOrConnect()
	if err != nil {
		return Result{HostIP: c.Host.IP, Err: err, Code: -1}
	}

	start := time.Now()
	s, err := cli.NewSession()
	if err != nil {
		return Result{HostIP: c.Host.IP, Err: err, Code: -1}
	}
	defer s.Close()

	stdoutPipe, _ := s.StdoutPipe()
	stderrPipe, _ := s.StderrPipe()

	runCmd := cmd.Raw
	if cmd.Shell {
		runCmd = pathWrap(runCmd)
	}

	go scanLines(stdoutPipe, onStdout)
	go scanLines(stderrPipe, onStderr)

	done := make(chan error, 1)
	go func() { done <- s.Run(runCmd) }()

	var e error
	select {
	case <-ctx.Done():
		_ = s.Signal(gossh.SIGKILL)
		e = ctx.Err()
	case e = <-done:
	}

	return Result{
		HostIP: c.Host.IP,
		Err:    e,
		Code:   exitCode(e),
		Spent:  time.Since(start),
	}
}

func scanLines(r io.Reader, cb func(string)) {
	if cb == nil || r == nil {
		return
	}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		cb(sc.Text())
	}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*gossh.ExitError); ok {
		return ee.ExitStatus()
	}
	return -1
}
