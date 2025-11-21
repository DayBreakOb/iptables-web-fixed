package service

import (
	"errors"
	"strings"

	"iptables-web/backend/internal/crypto"
	"iptables-web/backend/internal/models"
	"iptables-web/backend/internal/repo"
)

type HostsService struct{ r *repo.HostRepo }

func NewHostsService() *HostsService { return &HostsService{r: repo.NewHostRepo()} }

// ============ 查询 ============
func (s *HostsService) List() ([]models.Host, error) {
	hs, err := s.r.List()
	if err != nil {
		return nil, err
	}
	for i := range hs {
		hs[i].Normalize()
	}
	return hs, nil
}
func (s *HostsService) Get(id uint) (*models.Host, error) {
	h, err := s.r.Get(id)
	if err != nil {
		return nil, err
	}
	h.Normalize()
	return h, nil
}

// ============ 创建 ============
type CreateHostInput struct {
	Name, IP           string
	Port               int
	LoginMethod        string // "user" | "sudo" | "root"
	User, Password     string
	RootUser, RootPass string
}

func (s *HostsService) Create(in CreateHostInput) (*models.Host, error) {
	in.LoginMethod = strings.ToLower(strings.TrimSpace(in.LoginMethod))
	// 去重：同名 / 同 IP+端口
	if h, err := s.r.FindByName(strings.TrimSpace(in.Name)); err == nil && h != nil {
		return nil, errors.New("host name already exists")
	}
	if h, err := s.r.FindByIPPort(strings.TrimSpace(in.IP), defPort(in.Port)); err == nil && h != nil {
		return nil, errors.New("ip:port already exists")
	}

	m := models.Host{
		Name:        strings.TrimSpace(in.Name),
		IP:          strings.TrimSpace(in.IP),
		Port:        defPort(in.Port),
		LoginMethod: in.LoginMethod,
		User:        strings.TrimSpace(in.User),
		RootUser:    strings.TrimSpace(in.RootUser),
	}
	encUserPass, err := crypto.Seal(strings.TrimSpace(in.Password)) // 允许空串
	if err != nil {
		return nil, err
	}
	encRootPass, err := crypto.Seal(strings.TrimSpace(in.RootPass))
	if err != nil {
		return nil, err
	}
	m.Password = encUserPass
	m.RootPass = encRootPass
	m.Normalize()

	if err := s.r.Create(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

// ============ 修改 ============
type UpdateHostInput struct {
	ID          uint
	Name, IP    string
	Port        int
	LoginMethod string // "user" | "sudo" | "root"
	User        string
	Password    string // 留空表示不改
	RootUser    string
	RootPass    string // 留空表示不改
}

func (s *HostsService) Update(in UpdateHostInput) (*models.Host, error) {
	h, err := s.r.Get(in.ID)
	if err != nil {
		return nil, err
	}

	// 去重：排除自己
	if x, err := s.r.FindByName(strings.TrimSpace(in.Name)); err == nil && x != nil && x.ID != in.ID {
		return nil, errors.New("host name already exists")
	}
	if x, err := s.r.FindByIPPort(strings.TrimSpace(in.IP), defPort(in.Port)); err == nil && x != nil && x.ID != in.ID {
		return nil, errors.New("ip:port already exists")
	}

	h.Name = strings.TrimSpace(in.Name)
	h.IP = strings.TrimSpace(in.IP)
	h.Port = defPort(in.Port)
	h.LoginMethod = strings.ToLower(strings.TrimSpace(in.LoginMethod))
	h.User = strings.TrimSpace(in.User)
	h.RootUser = strings.TrimSpace(in.RootUser)

	// 密码留空不改；非空则重新加密
	if s := strings.TrimSpace(in.Password); s != "" {
		enc, err := crypto.Seal(s)
		if err != nil {
			return nil, err
		}
		h.Password = enc
	}
	if s := strings.TrimSpace(in.RootPass); s != "" {
		enc, err := crypto.Seal(s)
		if err != nil {
			return nil, err
		}
		h.RootPass = enc
	}

	h.Normalize()
	if err := s.r.Update(h); err != nil {
		return nil, err
	}
	return h, nil
}

// ============ 删除 ============
func (s *HostsService) Delete(id uint) error                  { return s.r.Delete(id) }
func (s *HostsService) BatchDelete(ids []uint) (int64, error) { return s.r.BatchDelete(ids) }

// utils
func defPort(p int) int {
	if p == 0 {
		return 22
	}
	return p
}
