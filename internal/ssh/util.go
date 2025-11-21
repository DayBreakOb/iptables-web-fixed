package ssh

import (
	"fmt"
	"sort"
	"strings"
)

func pathWrap(cmd string) string {
	return fmt.Sprintf("sh -lc 'PATH=/usr/sbin:/sbin:/usr/local/sbin:$PATH; %s'", cmd)
}

func envWrap(env map[string]string, cmd string) string {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, fmt.Sprintf("%s=%s", k, shellEscape(env[k])))
	}
	return strings.Join(pairs, " ") + " " + cmd
}

func shellEscape(s string) string {
	// 最简单的单引号逃逸
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func shortForLog(s string) string {
	if len(s) > 200 {
		return s[:200] + "...(truncated)"
	}
	return s
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
	if len(s) > 200 {
		s = s[len(s)-200:]
	}
	return strings.TrimSpace(s)
}
func trim1stLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) == 0 {
		return ""
	}
	return strings.TrimSpace(lines[0])
}
