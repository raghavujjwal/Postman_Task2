package main

import (
	"fmt"
	"log"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func initDB() {
	dsn  := "host=127.0.0.1 user=ujjwal password=secret dbname=recruit_portal port=5432 sslmode=disable"

	var err error

	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal(" Failed to connect to DB:", err)
	}

	fmt.Println(" Connected to PostgreSQL")

	// 🚀 Run auto migration here
	err = DB.AutoMigrate(
		&User{},
		&Company{},
		&Job{},
		&Application{},
		&InterviewRequest{},
	)
	if err != nil {
		log.Fatal(" Auto migration failed:", err)
	}
}
