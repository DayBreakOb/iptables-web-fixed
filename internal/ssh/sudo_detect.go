package ssh

import "strings"

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
		"需要密码",
		"password is required",
		"a password is required",
		"sudo: a password is required",
		"password:",
		"sudo: password for",
		"authentication failure",
		"sorry, you must have a tty",
	}
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	if strings.Contains(s, "sudo:") && (strings.Contains(s, "password") || strings.Contains(s, "需要")) {
		return true
	}
	return false
}
