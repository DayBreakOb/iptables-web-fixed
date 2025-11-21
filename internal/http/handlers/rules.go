package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"iptables-web/backend/internal/db"
	"iptables-web/backend/internal/models"
	"iptables-web/backend/internal/service"

	"github.com/gin-gonic/gin"
)

type rulesResp struct {
	Text string `json:"text"`
}
type RulesHandler struct{ svc *service.RulesService }

func NewRulesHandler() *RulesHandler { return &RulesHandler{svc: service.NewRulesService()} }

func (h *RulesHandler) Current(c *gin.Context) {
	hostID, _ := strconv.Atoi(c.Query("hostId"))
	v := c.Query("v")
	if hostID <= 0 || (v != "4" && v != "6") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "need hostId and v=4|6"})
		return
	}
	text, err := h.svc.CurrentRules(uint(hostID), v == "6")
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"hostId": hostID, "v": v, "text": text})
}

func (rh *RulesHandler) GetCurrentRules(c *gin.Context) {
	hostIDStr := c.Query("hostId")
	v := strings.TrimSpace(c.Query("v")) // "4" 或 "6"

	id, err := strconv.Atoi(hostIDStr)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid hostId"})
		return
	}

	// ★★ 关键：这里一定是 Host 模型，不是 receiver ★★
	var host models.Host
	if err := db.DB().First(&host, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
		return
	}

	// 调你自己的业务逻辑：要么传 host，要么传 host.ID
	text, err := rh.svc.CurrentRules(host.ID, v == "6")
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		c.JSON(http.StatusBadGateway, gin.H{"error": "iptables-save returned empty output"})
		return
	}

	c.JSON(http.StatusOK, rulesResp{Text: trimmed})
}

func (h *RulesHandler) GetCurrentRulesView(c *gin.Context) {
	id, _ := strconv.Atoi(c.Query("hostId"))
	v6 := c.Query("v") == "6"
	view, err := h.svc.CurrentRulesView(uint(id), v6)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, view)
}
