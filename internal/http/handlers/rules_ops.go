package handlers

import (
	"strconv"
	"strings"

	"iptables-web/backend/internal/service"

	"github.com/gin-gonic/gin"
)

type RuleOpReq struct {
	HostID uint   `json:"hostId" binding:"required"`
	V      string `json:"v"      binding:"required,oneof=4 6"`
	Table  string `json:"table"  binding:"omitempty,oneof=filter nat mangle raw security"`
	Chain  string `json:"chain"`
	Num    int    `json:"num"`
	Rule   string `json:"rule"`
	Pos    int    `json:"pos"`
}

type RulesOpsHandler struct{ svc *service.RulesOpsService }

func NewRulesOpsHandler() *RulesOpsHandler { return &RulesOpsHandler{svc: &service.RulesOpsService{}} }

func (h *RulesOpsHandler) Flush(c *gin.Context) {
	var r RuleOpReq
	if err := c.ShouldBindJSON(&r); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(r.Table) == "" {
		c.JSON(400, gin.H{"error": "table required"})
		return
	}
	if err := h.svc.Flush(r.HostID, r.V == "6", r.Table, r.Chain); err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}
func (h *RulesOpsHandler) Zero(c *gin.Context) {
	var r RuleOpReq
	if err := c.ShouldBindJSON(&r); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(r.Table) == "" {
		c.JSON(400, gin.H{"error": "table required"})
		return
	}
	if err := h.svc.Zero(r.HostID, r.V == "6", r.Table, r.Chain); err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}
func (h *RulesOpsHandler) ClearUserChains(c *gin.Context) {
	var r RuleOpReq
	if err := c.ShouldBindJSON(&r); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(r.Table) == "" {
		c.JSON(400, gin.H{"error": "table required"})
		return
	}
	if err := h.svc.ClearUserChains(r.HostID, r.V == "6", r.Table); err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}
func (h *RulesOpsHandler) Append(c *gin.Context) {
	var r RuleOpReq
	if err := c.ShouldBindJSON(&r); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if r.Table == "" || r.Chain == "" || strings.TrimSpace(r.Rule) == "" {
		c.JSON(400, gin.H{"error": "table, chain, rule required"})
		return
	}
	if err := h.svc.Append(r.HostID, r.V == "6", r.Table, r.Chain, r.Rule); err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}
func (h *RulesOpsHandler) Insert(c *gin.Context) {
	var r RuleOpReq
	if err := c.ShouldBindJSON(&r); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if r.Table == "" || r.Chain == "" || r.Pos <= 0 || strings.TrimSpace(r.Rule) == "" {
		c.JSON(400, gin.H{"error": "table, chain, pos, rule required"})
		return
	}
	if err := h.svc.Insert(r.HostID, r.V == "6", r.Table, r.Chain, r.Pos, r.Rule); err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}
func (h *RulesOpsHandler) Delete(c *gin.Context) {
	var r RuleOpReq
	if err := c.ShouldBindJSON(&r); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if r.Table == "" || r.Chain == "" || r.Num <= 0 {
		c.JSON(400, gin.H{"error": "table, chain, num required"})
		return
	}
	if err := h.svc.Delete(r.HostID, r.V == "6", r.Table, r.Chain, r.Num); err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}
func (h *RulesOpsHandler) Export(c *gin.Context) {
	id, _ := strconv.Atoi(c.Query("hostId"))
	v6 := c.Query("v") == "6"
	text, err := h.svc.Export(uint(id), v6)
	if err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.String(200, text)
}
func (h *RulesOpsHandler) Import(c *gin.Context) {
	var r struct {
		HostID  uint   `json:"hostId"`
		V       string `json:"v"`
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&r); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := h.svc.Import(r.HostID, r.V == "6", r.Content); err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}
