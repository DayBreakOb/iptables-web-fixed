package models

import (
	"strings"
	"time"
)

type Host struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// 名称唯一（业务上更直观，也便于前端提示），可根据需要去掉 uniqueIndex
	Name string `json:"name" gorm:"type:varchar(64);uniqueIndex"`

	// ip+port 组合唯一
	IP   string `json:"ip"   gorm:"type:varchar(128);index:idx_ip_port,priority:1"`
	Port int    `json:"port" gorm:"default:22;index:idx_ip_port,priority:2"`

	// 登录方式：user(普通账号，无sudo) | sudo(普通账号+sudo) | root(root直登)
	LoginMethod string `json:"login_method" gorm:"type:varchar(16);default:sudo"`

	// 普通账号
	User     string `json:"user"       gorm:"type:varchar(64)"`
	Password string `json:"-"          gorm:"type:text"` // AES-GCM 密文

	// root 直登账号
	RootUser string `json:"root_user"  gorm:"type:varchar(64)"`
	RootPass string `json:"-"          gorm:"type:text"` // AES-GCM 密文

	// 兼容旧字段（已废弃）
	UseSudo bool `json:"use_sudo" gorm:"-"`
}

// 统一规整：小写 login_method、默认端口
func (h *Host) Normalize() {
	h.LoginMethod = strings.ToLower(strings.TrimSpace(h.LoginMethod))
	if h.Port == 0 {
		h.Port = 22
	}
}
