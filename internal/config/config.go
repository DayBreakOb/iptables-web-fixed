package config

import (
	"log"
	"os"
	"strings"
)

type Config struct {
	MasterKey   string
	SQLitePath  string
	BindAddr    string
	CORSOrigins []string
}

func Load() Config {
	cfg := Config{
		MasterKey:  os.Getenv("MASTER_KEY"),
		SQLitePath: os.Getenv("SQLITE_PATH"),
		BindAddr:   os.Getenv("BIND_ADDR"),
	}
	if cfg.MasterKey == "" {
		log.Fatal("MASTER_KEY is required (base64 32 bytes)")
	}
	if cfg.SQLitePath == "" {
		cfg.SQLitePath = "iptables.db"
	}
	if cfg.BindAddr == "" {
		cfg.BindAddr = ":8088"
	}
	cors := os.Getenv("CORS_ORIGINS")
	if cors == "" {
		cfg.CORSOrigins = []string{"http://localhost:5173"}
	} else {
		cfg.CORSOrigins = strings.Split(cors, ",")
	}
	return cfg
}
