package db

import (
	"iptables-web/backend/internal/models"
	"log"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var gdb *gorm.DB

func Init(path string) error {
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		return err
	}
	if err := db.AutoMigrate(&models.Host{}); err != nil {
		return err
	}
	gdb = db
	log.Printf("sqlite initialized at %s", path)
	return nil
}

func DB() *gorm.DB { return gdb }
