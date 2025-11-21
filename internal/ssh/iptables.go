package ssh

import (
	"context"
	"fmt"
	"strings"
)

func (c *Client) IptablesSave(v6 bool) (string, error) {
	bin := "/usr/sbin/iptables-save"
	if v6 {
		bin = "/usr/sbin/ip6tables-save"
	}
	r := c.Exec(context.Background(), bin, WithShell(true))
	if r.Err != nil {
		return "", fmt.Errorf("%s: %v %s", bin, r.Err, tail(r.Stderr))
	}
	return r.Stdout, nil
}

func (c *Client) Iptables(v6 bool, table string, args ...string) (string, error) {
	cap := c.ProbeCapabilities(context.Background())
	bin := cap.IptablesPath
	if v6 {
		bin = strings.ReplaceAll(bin, "iptables", "ip6tables")
	}
	full := bin + " -t " + table + " " + strings.Join(args, " ")
	r := c.Exec(context.Background(), full, WithShell(true))
	if r.Err != nil {
		return "", fmt.Errorf("%s: %v %s", full, r.Err, tail(r.Stderr))
	}
	return r.Stdout, nil
}

func (c *Client) IptablesRestore(v6 bool, content string) (string, error) {
	bin := "/usr/sbin/iptables-restore"
	if v6 {
		bin = "/usr/sbin/ip6tables-restore"
	}
	r := c.Exec(context.Background(), bin, WithShell(true), WithStdin(content))
	if r.Err != nil {
		return "", fmt.Errorf("%s: %v %s", bin, r.Err, tail(r.Stderr))
	}
	return r.Stdout, nil
}
