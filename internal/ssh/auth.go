package ssh

import (
	"fmt"
	"io/ioutil"
	"strings"

	"iptables-web/backend/internal/crypto"
	"iptables-web/backend/internal/models"

	gossh "golang.org/x/crypto/ssh"
)

type AuthProvider interface {
	// 返回 user + auth methods
	Methods(h models.Host) (string, []gossh.AuthMethod, error)
	Name() string
}

// PasswordAuth：密码登录（root/sudo/user 都走它）
type PasswordAuth struct{}

func (a PasswordAuth) Name() string { return "password" }

func (a PasswordAuth) Methods(h models.Host) (string, []gossh.AuthMethod, error) {
	method := normalize(h.LoginMethod)
	switch method {
	case "root":
		user := firstNonEmpty(h.RootUser, "root")
		pass := crypto.MustOpen(h.RootPass)
		return user, []gossh.AuthMethod{gossh.Password(pass)}, nil
	case "sudo", "user", "":
		user := h.User
		pass := crypto.MustOpen(h.Password)
		return user, []gossh.AuthMethod{gossh.Password(pass)}, nil
	default:
		return "", nil, fmt.Errorf("unknown login_method: %s", h.LoginMethod)
	}
}

// KeyAuth：私钥登录（兼容未来）
type KeyAuth struct {
	PrivateKeyPath string
	Passphrase     string // 可选
	UserOverride   string // 可选，优先于 host.User
}

func (a KeyAuth) Name() string { return "key" }

func (a KeyAuth) Methods(h models.Host) (string, []gossh.AuthMethod, error) {
	keyBytes, err := ioutil.ReadFile(a.PrivateKeyPath)
	if err != nil {
		return "", nil, err
	}
	var signer gossh.Signer
	if strings.TrimSpace(a.Passphrase) != "" {
		signer, err = gossh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(a.Passphrase))
	} else {
		signer, err = gossh.ParsePrivateKey(keyBytes)
	}
	if err != nil {
		return "", nil, err
	}
	user := a.UserOverride
	if strings.TrimSpace(user) == "" {
		// root 也可以用 key 登录
		if normalize(h.LoginMethod) == "root" {
			user = firstNonEmpty(h.RootUser, "root")
		} else {
			user = h.User
		}
	}
	return user, []gossh.AuthMethod{gossh.PublicKeys(signer)}, nil
}
