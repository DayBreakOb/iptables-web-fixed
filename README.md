# iptables-web

多主机 iptables 读取控制台（Go + SQLite 后端，React 前端）。
- 后端：保存主机信息（账号/密码加密存储），通过 SSH 密码登录，支持普通账号+sudo 或 root 直登，读取 iptables/ip6tables 规则。
- 前端：新增主机、列主机、选择主机并获取规则，左侧分类按表/链展示。

## 后端运行
```bash
cd backend
cp .env.example .env
# 生成 32字节base64 主密钥
export MASTER_KEY=$(openssl rand -base64 32)
# 也可写入 .env
go mod tidy
make run
```

## 前端运行
```bash
cd frontend
npm i
npm run dev
```

## 目标机（普通账号+sudo 仅需读取时）
```
# /etc/sudoers.d/fwctl  （visudo -f 编辑）
Cmnd_Alias FWCMDS = /sbin/iptables-save, /sbin/ip6tables-save
fwops ALL=(root) NOPASSWD: FWCMDS
Defaults!FWCMDS !requiretty
```
