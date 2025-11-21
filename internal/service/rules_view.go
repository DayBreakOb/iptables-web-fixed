// internal/service/rules_view.go
package service

import (
	"bufio"
	"fmt"
	"iptables-web/backend/internal/repo"
	sshx "iptables-web/backend/internal/ssh"
	"regexp"
	"strings"
)

type RulesService struct{ hosts *repo.HostRepo }

func NewRulesService() *RulesService { return &RulesService{hosts: repo.NewHostRepo()} }

type RuleView struct {
	Num int    `json:"num"` // 在链中的生效顺序（1..N）
	Raw string `json:"raw"` // 原始 "-A CHAIN ..." 文本
}

type ChainView struct {
	Order    int        `json:"order"` // 该链在所在表里的出现顺序（0..）
	Name     string     `json:"name"`
	Policy   string     `json:"policy,omitempty"`   // ACCEPT/DROP/…；自定义链为 "-"
	Counters string     `json:"counters,omitempty"` // iptables-save 里的 "[pkts:bytes]" 原样
	Rules    []RuleView `json:"rules"`
}

type RulesView struct {
	// tables["nat"] = []ChainView{ ... }，按出现顺序排好
	Tables map[string][]ChainView `json:"tables"`
}

func (s *RulesService) CurrentRules(hostID uint, v6 bool) (string, error) {
	h, err := s.hosts.Get(hostID)
	if err != nil {
		return "", err
	}
	cli := sshx.Client{Host: *h}
	text, err := cli.IptablesSave(v6)
	if err != nil {
		return "", fmt.Errorf("fetch rules: %w", err)
	}
	return text, nil
}

// 提供“结构化视图”的方法
func (s *RulesService) CurrentRulesView(hostID uint, v6 bool) (*RulesView, error) {
	h, err := s.hosts.Get(hostID)
	if err != nil {
		return nil, err
	}
	cli := sshx.New(*h) // 或 &sshx.Client{Host:*h}
	text, err := cli.IptablesSave(v6)
	if err != nil {
		return nil, err
	}
	view := parseIptablesSave(text)
	return view, nil
}

// 放到同文件或单独 parser.go
func parseIptablesSave(text string) *RulesView {
	out := &RulesView{
		Tables: map[string][]ChainView{
			"raw": {}, "mangle": {}, "nat": {}, "filter": {}, "security": {},
		},
	}

	var curTable string
	// 记录某表里链名到下标的映射，便于往已有链里追加规则
	index := map[string]map[string]int{
		"raw": {}, "mangle": {}, "nat": {}, "filter": {}, "security": {},
	}

	// 正则更耐脏：":CHAIN POLICY [..]"；自定义链 policy 可能是 "-"
	reChain := regexp.MustCompile(`^:([^ ]+)\s+([A-Za-z-]+)\s+\[([^\]]*)\]$`)
	// 规则行："-A CHAIN ..."
	reRule := regexp.MustCompile(`^-A\s+(\S+)\s+(.*)$`)

	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// *table
		if strings.HasPrefix(line, "*") {
			curTable = strings.TrimPrefix(line, "*")
			continue
		}
		// COMMIT 结束当前表
		if line == "COMMIT" {
			curTable = ""
			continue
		}
		if curTable == "" {
			continue
		} // 其他表头不识别时跳过

		// 链
		if strings.HasPrefix(line, ":") {
			m := reChain.FindStringSubmatch(line)
			if len(m) == 4 {
				name := m[1]
				policy := m[2]
				counters := m[3]

				cv := ChainView{
					Order:    len(out.Tables[curTable]),
					Name:     name,
					Policy:   "",
					Counters: "",
					Rules:    make([]RuleView, 0, 8),
				}
				if policy != "-" {
					cv.Policy = policy
				}
				if counters != "" {
					cv.Counters = "[" + counters + "]"
				}

				out.Tables[curTable] = append(out.Tables[curTable], cv)
				if index[curTable] == nil {
					index[curTable] = map[string]int{}
				}
				index[curTable][name] = len(out.Tables[curTable]) - 1
			}
			continue
		}

		// 规则
		if strings.HasPrefix(line, "-A ") {
			m := reRule.FindStringSubmatch(line)
			if len(m) >= 2 {
				chain := m[1]
				// 若规则出现于链头之前，先补一条链（罕见，但容错）
				if _, ok := index[curTable][chain]; !ok {
					cv := ChainView{
						Order: len(out.Tables[curTable]),
						Name:  chain,
						Rules: make([]RuleView, 0, 8),
					}
					out.Tables[curTable] = append(out.Tables[curTable], cv)
					index[curTable][chain] = len(out.Tables[curTable]) - 1
				}
				ci := index[curTable][chain]
				rules := out.Tables[curTable][ci].Rules
				rules = append(rules, RuleView{
					Num: len(rules) + 1,
					Raw: line,
				})
				out.Tables[curTable][ci].Rules = rules
			}
			continue
		}
	}
	return out
}
