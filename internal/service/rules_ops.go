// internal/service/rules_ops.go
package service

import (
	"fmt"

	"iptables-web/backend/internal/repo"
	sshx "iptables-web/backend/internal/ssh"
)

type RulesOpsService struct {
	hosts *repo.HostRepo
}

func NewRulesOpsService() *RulesOpsService {
	return &RulesOpsService{hosts: repo.NewHostRepo()}
}

func (s *RulesOpsService) cli(hostID uint) (*sshx.Client, error) {
	h, err := s.hosts.Get(hostID)
	if err != nil {
		return nil, err
	}
	return sshx.New(*h), nil
}

// 清空规则：整表(-F) 或 指定链(-F CHAIN)
func (s *RulesOpsService) Flush(hostID uint, v6 bool, table, chain string) error {
	cli, err := s.cli(hostID)
	if err != nil {
		return err
	}
	if chain == "" {
		_, err = cli.Iptables(v6, table, "-F")
	} else {
		_, err = cli.Iptables(v6, table, "-F", chain)
	}
	return err
}

// 清零计数：整表(-Z) 或 指定链(-Z CHAIN)
func (s *RulesOpsService) Zero(hostID uint, v6 bool, table, chain string) error {
	cli, err := s.cli(hostID)
	if err != nil {
		return err
	}
	if chain == "" {
		_, err = cli.Iptables(v6, table, "-Z")
	} else {
		_, err = cli.Iptables(v6, table, "-Z", chain)
	}
	return err
}

// 清理自定义链：通常先 -F 再 -X
func (s *RulesOpsService) ClearUserChains(hostID uint, v6 bool, table string) error {
	cli, err := s.cli(hostID)
	if err != nil {
		return err
	}
	if _, err = cli.Iptables(v6, table, "-F"); err != nil {
		return err
	}
	_, err = cli.Iptables(v6, table, "-X")
	return err
}

// 追加规则：iptables -t <table> -A <chain> <spec>
func (s *RulesOpsService) Append(hostID uint, v6 bool, table, chain, rule string) error {
	cli, err := s.cli(hostID)
	if err != nil {
		return err
	}
	_, err = cli.Iptables(v6, table, "-A", chain, rule)
	return err
}

// 插入规则：iptables -t <table> -I <chain> <pos> <spec>
func (s *RulesOpsService) Insert(hostID uint, v6 bool, table, chain string, pos int, rule string) error {
	cli, err := s.cli(hostID)
	if err != nil {
		return err
	}
	_, err = cli.Iptables(v6, table, "-I", chain, fmt.Sprint(pos), rule)
	return err
}

// 删除第 N 条：iptables -t <table> -D <chain> <num>
func (s *RulesOpsService) Delete(hostID uint, v6 bool, table, chain string, num int) error {
	cli, err := s.cli(hostID)
	if err != nil {
		return err
	}
	_, err = cli.Iptables(v6, table, "-D", chain, fmt.Sprint(num))
	return err
}

// 导出规则：iptables-save / ip6tables-save
func (s *RulesOpsService) Export(hostID uint, v6 bool) (string, error) {
	cli, err := s.cli(hostID)
	if err != nil {
		return "", err
	}
	return cli.IptablesSave(v6)
}

// 导入规则：iptables-restore / ip6tables-restore
func (s *RulesOpsService) Import(hostID uint, v6 bool, content string) error {
	cli, err := s.cli(hostID)
	if err != nil {
		return err
	}
	_, err = cli.IptablesRestore(v6, content)
	return err
}
