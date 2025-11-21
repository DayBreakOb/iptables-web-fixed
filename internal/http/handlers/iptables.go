// internal/handlers/iptables.go
package handlers

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"

	"iptables-web/backend/internal/service"
)

type ChainDTO struct {
	Name    string `json:"name"`
	Policy  string `json:"policy,omitempty"`
	Builtin bool   `json:"builtin"`
}

type RuleDTO struct {
	ID         string   `json:"id"`
	Num        int      `json:"num"`
	Chain      string   `json:"chain"`
	Table      string   `json:"table"`
	Family     string   `json:"family"`
	Protocol   string   `json:"protocol"`
	SourceIP   string   `json:"sourceIp"`
	SourcePort string   `json:"sourcePort"`
	DestIP     string   `json:"destIp"`
	DestPort   string   `json:"destPort"`
	Action     string   `json:"action"`
	State      []string `json:"state"`
	Interface  string   `json:"interface"`
	ToPort     string   `json:"toPort"`
	ToSource   string   `json:"toSource"`
	Comment    string   `json:"comment,omitempty"`
	Spec       string   `json:"spec"`
}

// 请求体，与前端 src/types/iptables.ts 中的 ChainInput / RuleInput 对应
type createChainReq struct {
	Name string `json:"name" validate:"required,min=1,max=64"`
}

type createRuleReq struct {
	Num        *int     `json:"num" validate:"omitempty,gte=1"`
	Protocol   string   `json:"protocol" validate:"required"`
	SourceIP   string   `json:"sourceIp" validate:"omitempty"`
	SourcePort string   `json:"sourcePort" validate:"omitempty"`
	DestIP     string   `json:"destIp" validate:"omitempty"`
	DestPort   string   `json:"destPort" validate:"omitempty"`
	Action     string   `json:"action" validate:"required"`
	State      []string `json:"state" validate:"omitempty"`
	Interface  string   `json:"interface" validate:"omitempty"`
	ToPort     string   `json:"toPort" validate:"omitempty"`
	ToSource   string   `json:"toSource" validate:"omitempty"`
	Comment    string   `json:"comment" validate:"omitempty"`
}

type updateRuleReq = createRuleReq

type IptablesHandler struct {
	svc      *service.IptablesService
	validate *validator.Validate
}

func NewIptablesHandler() *IptablesHandler {
	return &IptablesHandler{
		svc:      service.NewIptablesService(),
		validate: validator.New(),
	}
}

func parseFamily(s string) service.IPFamily {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "ipv6" || s == "v6" || s == "6" {
		return service.FamilyIPv6
	}
	return service.FamilyIPv4
}

func parseTable(s string) service.TableType {
	return service.TableType(strings.ToLower(strings.TrimSpace(s)))
}

// GET /api/hosts/:id/iptables/:family/:table/chains
func (h *IptablesHandler) ListChains(c *gin.Context) {
	hostID, _ := strconv.Atoi(c.Param("id"))
	family := parseFamily(c.Param("family"))
	table := parseTable(c.Param("table"))

	cs, err := h.svc.ListChains(uint(hostID), family, table)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	out := make([]ChainDTO, 0, len(cs))
	for _, x := range cs {
		out = append(out, ChainDTO{
			Name:    x.Name,
			Policy:  x.Policy,
			Builtin: x.Builtin,
		})
	}
	c.JSON(http.StatusOK, gin.H{"chains": out})
}

// POST /api/hosts/:id/iptables/:family/:table/chains
func (h *IptablesHandler) CreateChain(c *gin.Context) {
	hostID, _ := strconv.Atoi(c.Param("id"))
	family := parseFamily(c.Param("family"))
	table := parseTable(c.Param("table"))

	var req createChainReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.validate.Struct(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.svc.CreateChain(uint(hostID), family, table, service.ChainInput{Name: req.Name}); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

// DELETE /api/hosts/:id/iptables/:family/:table/chains/:chain
func (h *IptablesHandler) DeleteChain(c *gin.Context) {
	hostID, _ := strconv.Atoi(c.Param("id"))
	family := parseFamily(c.Param("family"))
	table := parseTable(c.Param("table"))
	chainName, _ := urlDecode(c.Param("chain"))

	if err := h.svc.DeleteChain(uint(hostID), family, table, chainName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

// GET /api/hosts/:id/iptables/:family/:table/chains/:chain/rules
func (h *IptablesHandler) ListRules(c *gin.Context) {
	hostID, _ := strconv.Atoi(c.Param("id"))
	family := parseFamily(c.Param("family"))
	table := parseTable(c.Param("table"))
	chainName, _ := urlDecode(c.Param("chain"))

	rs, err := h.svc.ListRules(uint(hostID), family, table, chainName)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	out := make([]RuleDTO, 0, len(rs))
	for _, x := range rs {
		out = append(out, RuleDTO{
			ID:         x.ID,
			Num:        x.Num,
			Chain:      x.Chain,
			Table:      x.Table,
			Family:     string(family),
			Protocol:   x.Protocol,
			SourceIP:   x.SourceIP,
			SourcePort: x.SourcePort,
			DestIP:     x.DestIP,
			DestPort:   x.DestPort,
			Action:     x.Action,
			State:      x.State,
			Interface:  x.Interface,
			ToPort:     x.ToPort,
			ToSource:   x.ToSource,
			Comment:    x.Comment,
			Spec:       x.Spec,
		})
	}
	c.JSON(http.StatusOK, gin.H{"rules": out})
}

// POST /api/hosts/:id/iptables/:family/:table/chains/:chain/rules
func (h *IptablesHandler) CreateRule(c *gin.Context) {
	hostID, _ := strconv.Atoi(c.Param("id"))
	family := parseFamily(c.Param("family"))
	table := parseTable(c.Param("table"))
	chainName, _ := urlDecode(c.Param("chain"))

	var req createRuleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.validate.Struct(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.svc.CreateRule(uint(hostID), family, table, chainName, service.RuleInput{
		Num:        req.Num,
		Protocol:   req.Protocol,
		SourceIP:   req.SourceIP,
		SourcePort: req.SourcePort,
		DestIP:     req.DestIP,
		DestPort:   req.DestPort,
		Action:     req.Action,
		State:      req.State,
		Interface:  req.Interface,
		ToPort:     req.ToPort,
		ToSource:   req.ToSource,
		Comment:    req.Comment,
	}); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

// PUT /api/hosts/:id/iptables/:family/:table/chains/:chain/rules/:ruleId
func (h *IptablesHandler) UpdateRule(c *gin.Context) {
	hostID, _ := strconv.Atoi(c.Param("id"))
	family := parseFamily(c.Param("family"))
	table := parseTable(c.Param("table"))
	chainName, _ := urlDecode(c.Param("chain"))
	ruleID, _ := urlDecode(c.Param("ruleId"))

	var req updateRuleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.validate.Struct(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.svc.UpdateRule(uint(hostID), family, table, chainName, ruleID, service.RuleInput{
		Num:        req.Num,
		Protocol:   req.Protocol,
		SourceIP:   req.SourceIP,
		SourcePort: req.SourcePort,
		DestIP:     req.DestIP,
		DestPort:   req.DestPort,
		Action:     req.Action,
		State:      req.State,
		Interface:  req.Interface,
		ToPort:     req.ToPort,
		ToSource:   req.ToSource,
		Comment:    req.Comment,
	}); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

// DELETE /api/hosts/:id/iptables/:family/:table/chains/:chain/rules/:ruleId
func (h *IptablesHandler) DeleteRule(c *gin.Context) {
	hostID, _ := strconv.Atoi(c.Param("id"))
	family := parseFamily(c.Param("family"))
	table := parseTable(c.Param("table"))
	chainName, _ := urlDecode(c.Param("chain"))
	ruleID, _ := urlDecode(c.Param("ruleId"))

	if err := h.svc.DeleteRule(uint(hostID), family, table, chainName, ruleID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

// DELETE /api/hosts/:id/iptables/:family/:table/chains/:chain/rules  （清空链）
func (h *IptablesHandler) ClearChain(c *gin.Context) {
	hostID, _ := strconv.Atoi(c.Param("id"))
	family := parseFamily(c.Param("family"))
	table := parseTable(c.Param("table"))
	chainName, _ := urlDecode(c.Param("chain"))

	if err := h.svc.ClearChain(uint(hostID), family, table, chainName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

// 小工具：对 URL path 中 encodeURIComponent 的内容解码
func urlDecode(s string) (string, error) {
	return url.PathUnescape(s)
}
