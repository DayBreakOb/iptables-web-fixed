package ssh

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"iptables-web/backend/internal/crypto"
	"iptables-web/backend/internal/models"

	gossh "golang.org/x/crypto/ssh"
)

type Client struct{ Host models.Host }

func New(h models.Host) *Client {
	return &Client{Host: h}
}

func (c *Client) dial(user, pass string) (*gossh.Client, error) {
	conf := &gossh.ClientConfig{
		User:            user,
		Auth:            []gossh.AuthMethod{gossh.Password(pass)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), // TODO: 生产环境改为 known_hosts 校验
		Timeout:         10 * time.Second,
	}
	addr := fmt.Sprintf("%s:%d", c.Host.IP, portOrDefault(c.Host.Port))
	log.Printf("[ssh] dial %s@%s", user, addr)
	return gossh.Dial("tcp", addr, conf)
}

// 普通命令执行（非交互）
func (c *Client) run(cmd, user, pass, stdin string) (string, string, error) {
	cli, err := c.dial(user, pass)
	if err != nil {
		return "", "", err
	}
	defer cli.Close()

	s, err := cli.NewSession()
	if err != nil {
		return "", "", err
	}
	defer s.Close()

	var out, errb bytes.Buffer
	s.Stdout = &out
	s.Stderr = &errb
	if stdin != "" {
		s.Stdin = strings.NewReader(stdin)
	}

	log.Printf("[ssh] run user=%s cmd=%q", user, cmd)
	e := s.Run(cmd)
	log.Printf("[ssh] run done user=%s cmd=%q err=%v stdout=%dB stderr=%dB",
		user, cmd, e, out.Len(), errb.Len())

	if e != nil {
		return out.String(), errb.String(), e
	}
	return out.String(), errb.String(), nil
}

// 需要 PTY 的交互式执行（用于 su - root，需要喂密码）
func (c *Client) runPTY(cmd, user, pass, stdin string) (string, string, error) {
	cli, err := c.dial(user, pass)
	if err != nil {
		return "", "", err
	}
	defer cli.Close()

	s, err := cli.NewSession()
	if err != nil {
		return "", "", err
	}
	defer s.Close()

	// su 大多需要 TTY
	if err := s.RequestPty("xterm", 80, 24, gossh.TerminalModes{
		gossh.ECHO:          0,
		gossh.TTY_OP_ISPEED: 14400,
		gossh.TTY_OP_OSPEED: 14400,
	}); err != nil {
		return "", "", fmt.Errorf("request pty: %w", err)
	}

	var out, errb bytes.Buffer
	s.Stdout = &out
	s.Stderr = &errb

	in, _ := s.StdinPipe()
	if stdin != "" {
		// 简化：稍等片刻再输入密码；如需更稳可读取提示再输入
		go func() {
			time.Sleep(150 * time.Millisecond)
			io.WriteString(in, stdin)
		}()
	}

	log.Printf("[ssh] run(pty) user=%s cmd=%q", user, cmd)
	e := s.Run(cmd)
	log.Printf("[ssh] run(pty) done user=%s cmd=%q err=%v stdout=%dB stderr=%dB",
		user, cmd, e, out.Len(), errb.Len())

	if e != nil {
		return out.String(), errb.String(), e
	}
	return out.String(), errb.String(), nil
}

// 为了避免普通用户环境缺少 /usr/sbin，这里统一在 shell 里补 PATH
func pathCmd(bin string) string {
	return fmt.Sprintf("sh -lc 'PATH=/usr/sbin:/sbin:/usr/local/sbin:$PATH; %s'", bin)
}

func (c *Client) IptablesSave(v6 bool) (string, error) {
	bin := "/usr/sbin/iptables-save"
	if v6 {
		bin = "/usr/sbin/ip6tables-save"
	}
	cmd := pathCmd(bin)

	method := strings.ToLower(strings.TrimSpace(c.Host.LoginMethod))
	log.Printf("[ssh] iptables-save method=%s v6=%v host=%s:%d",
		method, v6, c.Host.IP, portOrDefault(c.Host.Port))

	switch method {
	case "root":
		rp := crypto.MustOpen(c.Host.RootPass)
		out, errb, err := c.run(cmd, firstNonEmpty(c.Host.RootUser, "root"), rp, "")
		if err != nil {
			return "", fmt.Errorf("root %s: %v, stderr=%s", bin, err, tail(errb))
		}
		return out, nil

	case "sudo":
		up := crypto.MustOpen(c.Host.Password)
		user := c.Host.User

		// 1) 先尝试 NOPASSWD
		if out, errb, err := c.run("sudo -n "+cmd, user, up, ""); err == nil {
			return out, nil
		} else {
			// 记录 stderr 方便排查（避免记录密码）
			log.Printf("[ssh] sudo -n failed host=%s:%d user=%s stderr(len=%d)=%q",
				c.Host.IP, portOrDefault(c.Host.Port), user, len(errb), shortForLog(errb))
			// 如果失败并且不是需要密码或 requiretty 的情形，则直接返回错误
			if !looksLikeSudoNeedPassword(errb) && !looksLikeRequireTTY(errb) {
				return "", fmt.Errorf("sudo %s: %v, stderr=%s", bin, err, tail(errb))
			}
		}

		// 2) 需要密码：尝试通过 stdin 喂密码（sudo -S）
		out, errb, err := c.run("sudo -S -p '' "+cmd, user, up, up+"\n")
		if err == nil {
			return out, nil
		}
		log.Printf("[ssh] sudo -S failed host=%s:%d user=%s stderr(len=%d)=%q",
			c.Host.IP, portOrDefault(c.Host.Port), user, len(errb), shortForLog(errb))

		// 3) 如果 stderr 表示 sudo 要求 tty 或 sudo 从 /dev/tty 读密码，则使用 PTY
		if looksLikeRequireTTY(errb) || looksLikeSudoReadFromTTY(errb) {
			out2, errb2, err2 := c.runPTY(fmt.Sprintf(`sudo -S -p '' %s`, cmd), user, up, up+"\n")
			if err2 != nil {
				return "", fmt.Errorf("sudo(pty) %s: %v, stderr=%s", bin, err2, tail(errb2))
			}
			return out2, nil
		}

		// 4) 其它情况：返回 -S 的错误信息
		return "", fmt.Errorf("sudo(pass) %s: %v, stderr=%s", bin, err, tail(errb))

	case "user":
		up := crypto.MustOpen(c.Host.Password)
		rp := crypto.MustOpen(c.Host.RootPass)
		rootUser := firstNonEmpty(c.Host.RootUser, "root")
		out, errb, err := c.runPTY(fmt.Sprintf(`su - %s -c %q`, rootUser, cmd), c.Host.User, up, rp+"\n")
		if err != nil {
			return "", fmt.Errorf("su %s: %v, stderr=%s", bin, err, tail(errb))
		}
		return out, nil

	default:
		up := crypto.MustOpen(c.Host.Password)
		out, errb, err := c.run("sudo -n "+cmd, c.Host.User, up, "")
		if err != nil {
			return "", fmt.Errorf("default(sudo) %s: %v, stderr=%s", bin, err, tail(errb))
		}
		return out, nil
	}
}

func (c *Client) Iptables(v6 bool, table string, args ...string) (string, error) {
	bin := "/usr/sbin/iptables"
	if v6 {
		bin = "/usr/sbin/ip6tables"
	}
	// 组装：iptables -t nat -A chain <spec...>
	full := bin + " -t " + table + " " + strings.Join(args, " ")
	return c.execByMethod(v6, full, "") // 和 IptablesSave 用同样“按登录方式执行”的函数
}

func (c *Client) IptablesRestore(v6 bool, content string) (string, error) {
	bin := "/usr/sbin/iptables-restore"
	if v6 {
		bin = "/usr/sbin/ip6tables-restore"
	}
	// 从 stdin 喂入规则
	return c.execByMethod(v6, bin, content)
}

func (c *Client) execByMethod(v6 bool, rawCmd, stdin string) (string, error) {
	cmd := pathCmd(rawCmd) // 补 PATH
	method := strings.ToLower(strings.TrimSpace(c.Host.LoginMethod))
	user := c.Host.User
	//host := c.Host.IP
	//port := portOrDefault(c.Host.Port)

	switch method {
	case "root":
		rp := crypto.MustOpen(c.Host.RootPass)
		out, errb, err := c.run(cmd, firstNonEmpty(c.Host.RootUser, "root"), rp, stdin)
		if err != nil {
			return "", fmt.Errorf("%s: %v, %s", rawCmd, err, tail(errb))
		}
		return out, nil

	case "sudo":
		up := crypto.MustOpen(c.Host.Password)

		// 1) sudo -n
		out, errb, err := c.run("sudo -n "+cmd, user, up, stdin)
		if err == nil {
			return out, nil
		}

		// 如果错误不是因为需要密码或 TTY，直接返回
		if !needsSudoPassword(errb) && !looksLikeRequireTTY(errb) && !looksLikeSudoReadFromTTY(errb) {
			return "", fmt.Errorf("%s: %v, %s", rawCmd, err, tail(errb))
		}

		// 2) sudo -S
		out, errb, err = c.run("sudo -S -p '' "+cmd, user, up, stdin+up+"\n")
		if err == nil {
			return out, nil
		}

		// 如果需要 PTY，使用 runPTY
		if looksLikeRequireTTY(errb) || looksLikeSudoReadFromTTY(errb) {
			combinedStdin := stdin + up + "\n"
			out2, errb2, err2 := c.runPTY(fmt.Sprintf(`sudo -S -p '' %s`, cmd), user, up, combinedStdin)
			if err2 != nil {
				return "", fmt.Errorf("%s: %v, %s", rawCmd, err2, tail(errb2))
			}
			return out2, nil
		}

		// 否则返回 sudo -S 错误
		return "", fmt.Errorf("%s: %v, %s", rawCmd, err, tail(errb))

	case "user":
		up := crypto.MustOpen(c.Host.Password)
		rp := crypto.MustOpen(c.Host.RootPass)
		rootUser := firstNonEmpty(c.Host.RootUser, "root")
		out, errb, err := c.runPTY(fmt.Sprintf(`su - %s -c %q`, rootUser, cmd), c.Host.User, up, rp+"\n")
		if err != nil {
			return "", fmt.Errorf("%s: %v, %s", rawCmd, err, tail(errb))
		}
		return out, nil

	default:
		return "", fmt.Errorf("unknown login_method: %s", c.Host.LoginMethod)
	}
}

// ----- 辅助函数（与你上面提供的函数一致，但加了 needsSudoPassword 兼容） -----

func shortForLog(s string) string {
	if len(s) > 200 {
		return s[:200] + "...(truncated)"
	}
	return s
}

func looksLikeSudoNeedPassword(stderr string) bool {
	s := strings.ToLower(stderr)
	patterns := []string{
		"password is required",
		"a password is required",
		"需要密码",
		"password:",
		"sudo: a password is required",
		"authentication failure",
		"sorry, you must have a tty",
	}
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func looksLikeRequireTTY(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "no tty") ||
		strings.Contains(s, "a terminal is required") ||
		strings.Contains(s, "you must have a tty") ||
		strings.Contains(s, "requiretty") ||
		strings.Contains(s, "需要 tty")
}

func looksLikeSudoReadFromTTY(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "not a tty") ||
		strings.Contains(s, "no tty present") ||
		strings.Contains(s, "unable to allocate pty")
}

func needsSudoPassword(stderr string) bool {
	s := strings.ToLower(strings.TrimSpace(stderr))
	if s == "" {
		return false
	}

	patterns := []string{
		"需要密码",                 // 中文
		"password is required", // 英文变体
		"a password is required",
		"sudo: a password is required",
		"password:",          // 常见带冒号提示
		"sudo: password for", // sudo 常见提示 "sudo: password for <user>"
		"authentication failure",
		"sorry, you must have a tty", // 有时 also indicates auth issues
	}

	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}

	// 还有一种简短的中文 stderr： "sudo: 需要密码\n" — 上面 "需要密码" 已覆盖，
	// 但为保险再判断含有 "sudo:" 且含 "password" / "需要" 的组合
	if strings.Contains(s, "sudo:") && (strings.Contains(s, "password") || strings.Contains(s, "需要")) {
		return true
	}

	return false
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func portOrDefault(p int) int {
	if p == 0 {
		return 22
	}
	return p
}

func tail(s string) string {
	r := s
	if len(r) > 200 {
		r = r[len(r)-200:]
	}
	return strings.TrimSpace(r)
}
