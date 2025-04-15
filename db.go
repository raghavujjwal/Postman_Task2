package main

import (
	"fmt"
	"log"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var db *gorm.DB

func initDB() {
	// Get database connection parameters from environment variables
	// or use default values for development
	dbHost := getEnvOrDefault("DB_HOST", "db")          // Changed from "postgres" to "db"
    dbUser := getEnvOrDefault("DB_USER", "ujjwal")      // Changed from "postgres" to "ujjwal"
    dbPassword := getEnvOrDefault("DB_PASSWORD", "secret") // Changed from "postgres" to "secret"
    dbName := getEnvOrDefault("DB_NAME", "recruit_portal") // Changed from "jobportal" to "recruit_portal"
    dbPort := getEnvOrDefault("DB_PORT", "5432")

	// Construct connection string
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=UTC",
		dbHost, dbUser, dbPassword, dbName, dbPort)

	// Configure GORM logger
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			LogLevel:                  logger.Info, // Log level
			IgnoreRecordNotFoundError: true,        // Ignore ErrRecordNotFound error for logger
			Colorful:                  true,        // Enable color
		},
	)

	// Open database connection
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: newLogger,
	})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	fmt.Println("Connected to PostgreSQL")

	// Auto migrate database schema
	err = db.AutoMigrate(&User{}, &Company{}, &Job{}, &Application{}, &InterviewRequest{})
	if err != nil {
		log.Fatalf("Auto migration failed: %v", err)
	}
	fmt.Println("Database migration completed")

	// Load existing data from in-memory maps to database
	migrateExistingData()
}

// Helper function to get environment variable or use default value
func getEnvOrDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// Migrate existing in-memory data to database
func migrateExistingData() {
	// Migrate users
	for _, user := range users {
		db.Where("id = ?", user.ID).FirstOrCreate(&user)
	}

	// Migrate jobs
	for _, job := range jobs {
		db.Where("id = ?", job.ID).FirstOrCreate(&job)
	}

	// Migrate applications
	for jobID, applicantIDs := range jobApplications {
		for _, applicantID := range applicantIDs {
			application := Application{
				ID:          fmt.Sprintf("%s-%s", jobID, applicantID),
				JobID:       jobID,
				ApplicantID: applicantID,
				Status:      "pending",
			}
			db.Where("id = ?", application.ID).FirstOrCreate(&application)
		}
	}

	// Migrate interview requests
	for _, interview := range interviewRequests {
		db.Where("id = ?", interview.ID).FirstOrCreate(&interview)
	}
}