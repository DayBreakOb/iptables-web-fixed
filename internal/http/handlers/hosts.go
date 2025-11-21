package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"

	"iptables-web/backend/internal/service"
)

type HostDTO struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	IP          string `json:"ip"`
	Port        int    `json:"port"`
	User        string `json:"user"`
	RootUser    string `json:"root_user"`
	LoginMethod string `json:"login_method"`
}

// 创建
type CreateHostReq struct {
	Name        string `json:"name" validate:"required,min=1,max=64"`
	IP          string `json:"ip" validate:"required,ip"`
	Port        int    `json:"port" validate:"omitempty,min=1,max=65535"`
	LoginMethod string `json:"login_method" validate:"required,oneof=user sudo root"`
	User        string `json:"user" validate:"omitempty"`
	Password    string `json:"password" validate:"omitempty"`
	RootUser    string `json:"root_user" validate:"omitempty"`
	RootPass    string `json:"root_pass" validate:"omitempty"`
}

// 修改（与创建一致，但密码可留空表示不改）
type UpdateHostReq = CreateHostReq

type HostsHandler struct {
	svc      *service.HostsService
	validate *validator.Validate
}

func NewHostsHandler() *HostsHandler {
	return &HostsHandler{svc: service.NewHostsService(), validate: validator.New()}
}

// GET /api/hosts
func (h *HostsHandler) List(c *gin.Context) {
	hs, err := h.svc.List()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	out := make([]HostDTO, 0, len(hs))
	for _, x := range hs {
		out = append(out, HostDTO{
			ID: x.ID, Name: x.Name, IP: x.IP, Port: portOrDefault(x.Port),
			User: x.User, RootUser: x.RootUser, LoginMethod: x.LoginMethod,
		})
	}
	c.JSON(http.StatusOK, out)
}

// GET /api/hosts/:id
func (h *HostsHandler) Get(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	host, err := h.svc.Get(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, HostDTO{
		ID: host.ID, Name: host.Name, IP: host.IP,
		Port: portOrDefault(host.Port), User: host.User,
		RootUser: host.RootUser, LoginMethod: host.LoginMethod,
	})
}

// POST /api/hosts
func (h *HostsHandler) Create(c *gin.Context) {
	var req CreateHostReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.validate.Struct(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	method := strings.ToLower(strings.TrimSpace(req.LoginMethod))
	// 业务校验（与前端一致）
	switch method {
	case "sudo":
		if strings.TrimSpace(req.User) == "" || strings.TrimSpace(req.Password) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "sudo 登录需要填写 普通账号 与 密码"})
			return
		}
		req.RootUser, req.RootPass = "", ""
	case "root":
		if strings.TrimSpace(req.RootUser) == "" || strings.TrimSpace(req.RootPass) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "root 登录需要填写 root 用户 与 密码"})
			return
		}
		req.User, req.Password = "", ""
	case "user":
		if strings.TrimSpace(req.User) == "" || strings.TrimSpace(req.Password) == "" ||
			strings.TrimSpace(req.RootUser) == "" || strings.TrimSpace(req.RootPass) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "普通账号登录需要填写 普通账号/密码 以及 root 用户/密码"})
			return
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "login_method 仅支持 user|sudo|root"})
		return
	}

	m, err := h.svc.Create(service.CreateHostInput{
		Name:        req.Name,
		IP:          req.IP,
		Port:        req.Port,
		LoginMethod: method,
		User:        req.User,
		Password:    req.Password,
		RootUser:    req.RootUser,
		RootPass:    req.RootPass,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, HostDTO{
		ID: m.ID, Name: m.Name, IP: m.IP, Port: portOrDefault(m.Port),
		User: m.User, RootUser: m.RootUser, LoginMethod: m.LoginMethod,
	})
}

// PUT /api/hosts/:id
func (h *HostsHandler) Update(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var req UpdateHostReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.validate.Struct(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	method := strings.ToLower(strings.TrimSpace(req.LoginMethod))
	// 与创建相同的业务校验，区别：密码可以留空表示不改
	switch method {
	case "sudo":
		if strings.TrimSpace(req.User) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "sudo 登录需要填写 普通账号"})
			return
		}
		req.RootUser = "" // root 字段不参与
	case "root":
		if strings.TrimSpace(req.RootUser) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "root 登录需要填写 root 用户"})
			return
		}
		req.User = ""
	case "user":
		if strings.TrimSpace(req.User) == "" || strings.TrimSpace(req.RootUser) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "普通账号登录需要填写 普通账号 以及 root 用户"})
			return
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "login_method 仅支持 user|sudo|root"})
		return
	}

	m, err := h.svc.Update(service.UpdateHostInput{
		ID:          uint(id),
		Name:        req.Name,
		IP:          req.IP,
		Port:        req.Port,
		LoginMethod: method,
		User:        req.User,
		Password:    strings.TrimSpace(req.Password), // 空串 => 不改
		RootUser:    req.RootUser,
		RootPass:    strings.TrimSpace(req.RootPass), // 空串 => 不改
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, HostDTO{
		ID: m.ID, Name: m.Name, IP: m.IP, Port: portOrDefault(m.Port),
		User: m.User, RootUser: m.RootUser, LoginMethod: m.LoginMethod,
	})
}

// DELETE /api/hosts/:id
func (h *HostsHandler) Delete(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	if err := h.svc.Delete(uint(id)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

// POST /api/hosts/batch-delete  { "ids": [1,2,3] }
type batchDeleteReq struct {
	IDs []uint `json:"ids" validate:"required,min=1,dive,gt=0"`
}

func (h *HostsHandler) BatchDelete(c *gin.Context) {
	var req batchDeleteReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.validate.Struct(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	affected, err := h.svc.BatchDelete(req.IDs)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": affected})
}

func portOrDefault(p int) int {
	if p == 0 {
		return 22
	}
	return p
}
