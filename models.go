package main

import (
    "github.com/lib/pq"
)



const (
    RoleSuperAdmin ="superadmin"
    RoleRecruiter   = "recruiter"
    RoleApplicant   = "applicant"
)

type User struct {
    ID        string   `gorm:"primaryKey"`
    Email     string   `gorm:"uniqueIndex;not null"`
    Name      string
    Role      string
    Approved  bool
    CompanyID *string
    Company   *Company `gorm:"foreignKey:CompanyID"`
    Skills    pq.StringArray `gorm:"type:text[]"`

    Applications []Application
    Jobs         []Job `gorm:"foreignKey:PostedByID"`
    Resume       string
}

type Company struct {
    ID          string `gorm:"primaryKey"`
    Name        string `gorm:"uniqueIndex;not null"`
    Description string
    LogoURL     string
    Approved    bool

    Recruiters []User `gorm:"foreignKey:CompanyID"`
    Jobs       []Job  `gorm:"foreignKey:CompanyID"`
}

type Job struct {
    ID          string `gorm:"primaryKey"`
    Title       string
    Description string
    Skills      pq.StringArray `gorm:"type:text[]"`
    CompanyID   string
    Company     Company
    PostedByID  string
    PostedBy    User `gorm:"foreignKey:PostedByID"`

    Applications []Application
}

type Application struct {
    ID          string `gorm:"primaryKey"`
    ApplicantID string
    Applicant   User `gorm:"foreignKey:ApplicantID"`
    JobID       string
    Job         Job
    ResumePath  string
    Status      string
}

type InterviewRequest struct {
    ID          string `gorm:"primaryKey"`
    JobID       string
    Job         Job
    ApplicantID string
    Applicant   User `gorm:"foreignKey:ApplicantID"`
    ProposedTime string
    MeetLink     string
    RecruiterID  string
    Status       string
}
