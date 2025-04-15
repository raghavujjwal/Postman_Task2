package main

import (
    "github.com/lib/pq"
    _"gorm.io/gorm"
)



const (
	RoleSuperAdmin = "super_admin"
	RoleRecruiter  = "recruiter"
	RoleApplicant  = "applicant"
)

type User struct {
	ID         string         `gorm:"primaryKey"`
	Email      string         `gorm:"uniqueIndex"`
	Name       string
	Role       string
	Approved   bool
	CompanyID  *string
	Company    *Company       `gorm:"foreignKey:CompanyID"`
	Skills     pq.StringArray `gorm:"type:text[]"`
	Applications []Application `gorm:"foreignKey:ApplicantID"`   // GORM will use User.ID as reference by default
	Jobs         []Job        `gorm:"foreignKey:PostedByID"`     // Likewise
	Resume       string
}


type Company struct {
	ID          string `gorm:"primaryKey"`
	Name        string
	Description string
	LogoURL     string
	Approved    bool
	// Define Recruiters as a relationship without direct storage
	Recruiters  []User `gorm:"foreignKey:CompanyID;references:ID"`
	// Define Jobs as a relationship without direct storage
	Jobs        []Job  `gorm:"foreignKey:CompanyID;references:ID"`
}

type Job struct {
	ID           string         `gorm:"primaryKey"`
	Title        string
	Description  string
	Skills       pq.StringArray `gorm:"type:text[]"`
	CompanyID    string
	Company      Company         `gorm:"foreignKey:CompanyID"`
	PostedByID   string
	PostedBy     User            `gorm:"foreignKey:PostedByID"`
	Applications []Application   `gorm:"foreignKey:JobID"`
}

type Application struct {
	ID          string `gorm:"primaryKey"`
	JobID       string
	Job         Job    `gorm:"foreignKey:JobID;references:ID"`
	ApplicantID string
	Applicant   User   `gorm:"foreignKey:ApplicantID;references:ID"`
	Status      string
	// Add any additional fields needed for job applications
}

type InterviewRequest struct {
	ID           string `gorm:"primaryKey"`
	JobID        string
	Job          Job    `gorm:"foreignKey:JobID;references:ID"`
	ApplicantID  string
	Applicant    User   `gorm:"foreignKey:ApplicantID;references:ID"`
	ProposedTime string
	MeetLink     string
	RecruiterID  string
	Recruiter    User   `gorm:"foreignKey:RecruiterID;references:ID"`
	Status       string
}
