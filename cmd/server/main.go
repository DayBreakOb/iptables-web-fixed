package main

import (
	"log"
	"os"

	"iptables-web/backend/internal/config"
	"iptables-web/backend/internal/crypto"
	"iptables-web/backend/internal/db"
	"iptables-web/backend/internal/http/router"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {

	_ = godotenv.Load()
	cfg := config.Load()
	if err := crypto.Init(cfg.MasterKey); err != nil {
		log.Fatalf("init crypto: %v", err)
	}
	// Gin 模式
	if v := os.Getenv("GIN_MODE"); v != "" {
		gin.SetMode(v)
	} else {
		gin.SetMode(gin.DebugMode)
	}
	log.Printf("[boot] gin mode = %s", gin.Mode())

	// 读取 DB DSN（sqlite 用文件路径即可）
	// 支持两个变量名：DB_DSN 优先，没有则用 DB_PATH，仍无则默认本地文件
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		dsn = os.Getenv("DB_PATH")
	}
	if dsn == "" {
		dsn = "./iptables.db" // 默认 sqlite 文件
	}
	log.Printf("[boot] db dsn = %s", dsn)

	// 初始化数据库
	if err := db.Init(dsn); err != nil {
		log.Fatalf("init db: %v", err)
	}

	// 路由
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	router.Register(r)

	// 启动 HTTP
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8088"
	}
	log.Printf("[boot] http listen on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("http run: %v", err)
	}
}
