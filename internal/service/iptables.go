// internal/service/iptables.go
package service

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"

	"iptables-web/backend/internal/repo"
	"iptables-web/backend/internal/ssh"
)

// IPFamily / TableType 可以只用 string，也可以自己定义新 type
type IPFamily string
type TableType string

const (
	FamilyIPv4 IPFamily = "ipv4"
	FamilyIPv6 IPFamily = "ipv6"
)

// Chain / Rule 结构与前端 types/iptables.ts 对应
type Chain struct {
	Name    string `json:"name"`
	Policy  string `json:"policy,omitempty"`
	Builtin bool   `json:"builtin"` // policy != "-" 基本就是内置链
}

type Rule struct {
	ID         string   `json:"id"`         // 这里用 "CHAIN:NUM"
	Num        int      `json:"num"`        // 行号
	Chain      string   `json:"chain"`      // 链名
	Table      string   `json:"table"`      // 表名
	Family     string   `json:"family"`     // ipv4/ipv6
	Protocol   string   `json:"protocol"`   // tcp/udp/icmp/all
	SourceIP   string   `json:"sourceIp"`   // 源 IP
	SourcePort string   `json:"sourcePort"` // 源端口
	DestIP     string   `json:"destIp"`     // 目标 IP
	DestPort   string   `json:"destPort"`   // 目标端口
	Action     string   `json:"action"`     // ACCEPT/DROP/REJECT/DNAT/SNAT等
	State      []string `json:"state"`      // 连接状态：NEW,ESTABLISHED,RELATED
	Interface  string   `json:"interface"`  // 接口
	ToPort     string   `json:"toPort"`     // DNAT/REDIRECT 的目标端口
	ToSource   string   `json:"toSource"`   // SNAT/MASQUERADE 的目标地址
	Comment    string   `json:"comment"`    // 注释
	Spec       string   `json:"spec"`       // 原始规则字符串（用于显示和兼容）
}

type ChainInput struct {
	Name string `json:"name"`
	// Policy 暂时只用于内置链的策略展示，创建自定义链时不用
	Policy string `json:"policy,omitempty"`
}

type RuleInput struct {
	Num        *int     `json:"num,omitempty"` // nil/0 表示追加（-A），>0 表示插入（-I num）
	Protocol   string   `json:"protocol"`      // tcp/udp/icmp/all
	SourceIP   string   `json:"sourceIp"`      // 源 IP
	SourcePort string   `json:"sourcePort"`    // 源端口
	DestIP     string   `json:"destIp"`        // 目标 IP
	DestPort   string   `json:"destPort"`      // 目标端口
	Action     string   `json:"action"`        // ACCEPT/DROP/REJECT/DNAT/SNAT等
	State      []string `json:"state"`         // 连接状态
	Interface  string   `json:"interface"`     // 接口
	ToPort     string   `json:"toPort"`        // DNAT 目标端口
	ToSource   string   `json:"toSource"`      // SNAT 目标地址
	Comment    string   `json:"comment"`       // 注释
}

// IptablesService：按 hostId 取 Host，再通过 ssh.Client 去调用 iptables
type IptablesService struct {
	hostRepo *repo.HostRepo
}

func NewIptablesService() *IptablesService {
	return &IptablesService{hostRepo: repo.NewHostRepo()}
}

func (s *IptablesService) sshClient(hostID uint) (*ssh.Client, error) {
	h, err := s.hostRepo.Get(hostID)
	if err != nil {
		return nil, err
	}
	h.Normalize()
	return ssh.New(*h), nil
}

func (s *IptablesService) boolFamily(family IPFamily) bool {
	return strings.ToLower(string(family)) == "ipv6"
}

// ============ 查询 ============

// ListChains 返回某个 host / family / table 下的链列表
func (s *IptablesService) ListChains(hostID uint, family IPFamily, table TableType) ([]Chain, error) {
	cli, err := s.sshClient(hostID)
	if err != nil {
		return nil, err
	}
	dump, err := cli.IptablesSave(s.boolFamily(family))
	if err != nil {
		return nil, err
	}
	chains, _ := parseTable(dump, string(table))
	return chains, nil
}

// ListRules 返回某个链下的规则列表
func (s *IptablesService) ListRules(hostID uint, family IPFamily, table TableType, chainName string) ([]Rule, error) {
	cli, err := s.sshClient(hostID)
	if err != nil {
		return nil, err
	}
	dump, err := cli.IptablesSave(s.boolFamily(family))
	if err != nil {
		return nil, err
	}
	_, rules := parseTable(dump, string(table))

	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if r.Chain == chainName {
			out = append(out, r)
		}
	}
	return out, nil
}

// ============ 链管理 ============

func (s *IptablesService) CreateChain(hostID uint, family IPFamily, table TableType, in ChainInput) error {
	cli, err := s.sshClient(hostID)
	if err != nil {
		return err
	}
	args := []string{"-N", in.Name}
	_, err = cli.Iptables(s.boolFamily(family), string(table), args...)
	return err
}

func (s *IptablesService) DeleteChain(hostID uint, family IPFamily, table TableType, chainName string) error {
	cli, err := s.sshClient(hostID)
	if err != nil {
		return err
	}
	// 注意：需要确保链已经被 flush 且无引用，否则 iptables -X 会失败
	_, err = cli.Iptables(s.boolFamily(family), string(table), "-X", chainName)
	return err
}

func (s *IptablesService) ClearChain(hostID uint, family IPFamily, table TableType, chainName string) error {
	cli, err := s.sshClient(hostID)
	if err != nil {
		return err
	}
	_, err = cli.Iptables(s.boolFamily(family), string(table), "-F", chainName)
	return err
}

// ============ 规则管理 ============

func buildIptablesArgs(in RuleInput) []string {
	args := []string{}

	// 协议
	if in.Protocol != "" && in.Protocol != "all" {
		args = append(args, "-p", in.Protocol)
	}

	// 源 IP
	if in.SourceIP != "" {
		args = append(args, "-s", in.SourceIP)
	}

	// 源端口
	if in.SourcePort != "" && in.Protocol != "" && in.Protocol != "all" {
		args = append(args, "--sport", in.SourcePort)
	}

	// 目标 IP
	if in.DestIP != "" {
		args = append(args, "-d", in.DestIP)
	}

	// 目标端口
	if in.DestPort != "" && in.Protocol != "" && in.Protocol != "all" {
		args = append(args, "--dport", in.DestPort)
	}

	// 连接状态
	if len(in.State) > 0 {
		args = append(args, "-m", "conntrack", "--ctstate", strings.Join(in.State, ","))
	}

	// 接口
	if in.Interface != "" {
		args = append(args, "-i", in.Interface)
	}

	// 动作
	if in.Action != "" {
		args = append(args, "-j", in.Action)

		// DNAT 需要 --to-destination
		if in.Action == "DNAT" && (in.ToSource != "" || in.ToPort != "") {
			dest := in.ToSource
			if in.ToPort != "" {
				if dest == "" {
					dest = ":" + in.ToPort
				} else {
					dest = dest + ":" + in.ToPort
				}
			}
			if dest != "" {
				args = append(args, "--to-destination", dest)
			}
		}

		// SNAT 需要 --to-source
		if in.Action == "SNAT" && in.ToSource != "" {
			args = append(args, "--to-source", in.ToSource)
		}

		// REDIRECT 需要 --to-ports
		if in.Action == "REDIRECT" && in.ToPort != "" {
			args = append(args, "--to-ports", in.ToPort)
		}
	}

	// 注释
	if in.Comment != "" {
		args = append(args, "-m", "comment", "--comment", in.Comment)
	}

	return args
}

func parseRuleSpec(spec string) (protocol, sourceIP, sourcePort, destIP, destPort, action, iface, toPort, toSource string, state []string) {
	parts := strings.Fields(spec)

	for i := 0; i < len(parts); i++ {
		switch parts[i] {
		case "-p":
			if i+1 < len(parts) {
				protocol = parts[i+1]
				i++
			}
		case "-s":
			if i+1 < len(parts) {
				sourceIP = parts[i+1]
				i++
			}
		case "--sport", "--source-port":
			if i+1 < len(parts) {
				sourcePort = parts[i+1]
				i++
			}
		case "-d":
			if i+1 < len(parts) {
				destIP = parts[i+1]
				i++
			}
		case "--dport", "--destination-port":
			if i+1 < len(parts) {
				destPort = parts[i+1]
				i++
			}
		case "-j":
			if i+1 < len(parts) {
				action = parts[i+1]
				i++
			}
		case "-i":
			if i+1 < len(parts) {
				iface = parts[i+1]
				i++
			}
		case "--ctstate":
			if i+1 < len(parts) {
				state = strings.Split(parts[i+1], ",")
				i++
			}
		case "--to-destination":
			if i+1 < len(parts) {
				dest := parts[i+1]
				if strings.Contains(dest, ":") {
					p := strings.Split(dest, ":")
					toSource = p[0]
					if len(p) > 1 {
						toPort = p[1]
					}
				} else {
					toSource = dest
				}
				i++
			}
		case "--to-source":
			if i+1 < len(parts) {
				toSource = parts[i+1]
				i++
			}
		case "--to-ports":
			if i+1 < len(parts) {
				toPort = parts[i+1]
				i++
			}
		}
	}

	if protocol == "" {
		protocol = "all"
	}

	return
}

// CreateRule：在链里插入/追加一条规则
func (s *IptablesService) CreateRule(hostID uint, family IPFamily, table TableType, chainName string, in RuleInput) error {
	cli, err := s.sshClient(hostID)
	if err != nil {
		return err
	}

	args := []string{}
	if in.Num != nil && *in.Num > 0 {
		args = append(args, "-I", chainName, strconv.Itoa(*in.Num))
	} else {
		args = append(args, "-A", chainName)
	}

	args = append(args, buildIptablesArgs(in)...)

	_, err = cli.Iptables(s.boolFamily(family), string(table), args...)
	return err
}

// UpdateRule：简单策略 = 先删旧规则，再在同一个位置插入新规则
func (s *IptablesService) UpdateRule(hostID uint, family IPFamily, table TableType, chainName string, ruleID string, in RuleInput) error {
	num, err := parseRuleNum(ruleID)
	if err != nil {
		return err
	}
	cli, err := s.sshClient(hostID)
	if err != nil {
		return err
	}

	// 先删旧
	if _, err := cli.Iptables(s.boolFamily(family), string(table), "-D", chainName, strconv.Itoa(num)); err != nil {
		return err
	}

	// 再插入新规则（固定插入到指定 num）
	n := num
	if in.Num != nil && *in.Num > 0 {
		n = *in.Num
	}
	return s.CreateRule(hostID, family, table, chainName, RuleInput{
		Num:        &n,
		Protocol:   in.Protocol,
		SourceIP:   in.SourceIP,
		SourcePort: in.SourcePort,
		DestIP:     in.DestIP,
		DestPort:   in.DestPort,
		Action:     in.Action,
		State:      in.State,
		Interface:  in.Interface,
		ToPort:     in.ToPort,
		ToSource:   in.ToSource,
		Comment:    in.Comment,
	})
}

func (s *IptablesService) DeleteRule(hostID uint, family IPFamily, table TableType, chainName string, ruleID string) error {
	num, err := parseRuleNum(ruleID)
	if err != nil {
		return err
	}
	cli, err := s.sshClient(hostID)
	if err != nil {
		return err
	}
	_, err = cli.Iptables(s.boolFamily(family), string(table), "-D", chainName, strconv.Itoa(num))
	return err
}

// ============ 解析 iptables-save ============

// parseTable 只解析指定表的数据，返回链和规则列表
func parseTable(dump string, table string) ([]Chain, []Rule) {
	var chains []Chain
	var rules []Rule

	scanner := bufio.NewScanner(strings.NewReader(dump))
	inTable := false
	ruleIndex := make(map[string]int) // chain -> num 累加

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "*") {
			cur := strings.TrimPrefix(line, "*")
			inTable = (cur == table)
			continue
		}
		if !inTable {
			continue
		}
		if line == "COMMIT" {
			inTable = false
			continue
		}

		// 链定义: :INPUT ACCEPT [0:0]
		if strings.HasPrefix(line, ":") {
			rest := strings.TrimPrefix(line, ":")
			parts := strings.Fields(rest)
			if len(parts) == 0 {
				continue
			}
			name := parts[0]
			policy := "-"
			if len(parts) > 1 {
				policy = parts[1]
			}
			chains = append(chains, Chain{
				Name:    name,
				Policy:  policy,
				Builtin: policy != "-",
			})
			continue
		}

		// 规则: -A INPUT -s 192.168... -j ACCEPT
		if strings.HasPrefix(line, "-A ") {
			rest := strings.TrimSpace(strings.TrimPrefix(line, "-A "))
			parts := strings.Fields(rest)
			if len(parts) == 0 {
				continue
			}
			chain := parts[0]
			spec := strings.TrimSpace(rest[len(chain):])

			ruleIndex[chain]++
			num := ruleIndex[chain]
			comment := parseComment(spec)

			protocol, sourceIP, sourcePort, destIP, destPort, action, iface, toPort, toSource, state := parseRuleSpec(spec)

			rules = append(rules, Rule{
				ID:         fmt.Sprintf("%s:%d", chain, num),
				Num:        num,
				Chain:      chain,
				Table:      table,
				Family:     "", // 由上层填，或前端自己知道
				Protocol:   protocol,
				SourceIP:   sourceIP,
				SourcePort: sourcePort,
				DestIP:     destIP,
				DestPort:   destPort,
				Action:     action,
				State:      state,
				Interface:  iface,
				ToPort:     toPort,
				ToSource:   toSource,
				Comment:    comment,
				Spec:       spec,
			})
		}
	}

	return chains, rules
}

func parseComment(spec string) string {
	i := strings.Index(spec, "--comment")
	if i < 0 {
		return ""
	}
	s := strings.TrimSpace(spec[i+len("--comment"):])
	if s == "" {
		return ""
	}
	// 尝试解析 "xxx" / 'xxx'
	if s[0] == '"' || s[0] == '\'' {
		quote := s[0]
		s = s[1:]
		if j := strings.IndexByte(s, quote); j >= 0 {
			return s[:j]
		}
		return s
	}
	// 退化：取下一个空格前
	parts := strings.Fields(s)
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

func parseRuleNum(id string) (int, error) {
	// 允许 "3" 或 "INPUT:3" 两种形式
	if n, err := strconv.Atoi(id); err == nil {
		return n, nil
	}
	if i := strings.LastIndex(id, ":"); i >= 0 {
		return strconv.Atoi(id[i+1:])
	}
	return 0, fmt.Errorf("invalid rule id: %s", id)
}
