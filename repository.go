package main

// User-related database functions

// GetUserByID retrieves a user by ID from the database
func GetUserByID(id string) (User, bool) {
	var user User
	result := db.Where("id = ?", id).First(&user)
	return user, result.Error == nil
}

// GetUserByEmail retrieves a user by email from the database
func GetUserByEmail(email string) (User, bool) {
	var user User
	result := db.Where("email = ?", email).First(&user)
	return user, result.Error == nil
}

// SaveUser saves or updates a user in the database
func SaveUser(user User) error {
	return db.Save(&user).Error
}

// Job-related database functions

// GetJobByID retrieves a job by ID from the database
func GetJobByID(id string) (Job, bool) {
	var job Job
	result := db.Where("id = ?", id).First(&job)
	return job, result.Error == nil
}

// GetJobsByRecruiter retrieves all jobs posted by a specific recruiter
func GetJobsByRecruiter(recruiterID string) ([]Job, error) {
	var jobs []Job
	result := db.Where("posted_by_id = ?", recruiterID).Find(&jobs)
	return jobs, result.Error
}

// SaveJob saves or updates a job in the database
func SaveJob(job Job) error {
	return db.Save(&job).Error
}

// Application-related database functions

// CreateApplication creates a new job application
func CreateApplication(jobID, applicantID string) error {
	application := Application{
		ID:          jobID + "-" + applicantID,
		JobID:       jobID,
		ApplicantID: applicantID,
		Status:      "pending",
	}
	return db.Create(&application).Error
}

// GetApplicationsByJob retrieves all applications for a specific job
func GetApplicationsByJob(jobID string) ([]Application, error) {
	var applications []Application
	result := db.Where("job_id = ?", jobID).Find(&applications)
	return applications, result.Error
}

// GetApplicationsByApplicant retrieves all applications made by a specific applicant
func GetApplicationsByApplicant(applicantID string) ([]Application, error) {
	var applications []Application
	result := db.Where("applicant_id = ?", applicantID).Find(&applications)
	return applications, result.Error
}

// HasApplied checks if a user has already applied to a job
func HasApplied(jobID, applicantID string) bool {
	var count int64
	db.Model(&Application{}).Where("job_id = ? AND applicant_id = ?", jobID, applicantID).Count(&count)
	return count > 0
}

// Company-related database functions

// GetCompanyByID retrieves a company by ID from the database
func GetCompanyByID(id string) (Company, bool) {
	var company Company
	result := db.Where("id = ?", id).First(&company)
	return company, result.Error == nil
}

// SaveCompany saves or updates a company in the database
func SaveCompany(company Company) error {
	return db.Save(&company).Error
}

// Interview request related functions

// CreateInterviewRequest creates a new interview request
func CreateInterviewRequest(request InterviewRequest) error {
	return db.Create(&request).Error
}

// GetInterviewRequestsByApplicant retrieves all interview requests for a specific applicant
func GetInterviewRequestsByApplicant(applicantID string) ([]InterviewRequest, error) {
	var requests []InterviewRequest
	result := db.Where("applicant_id = ?", applicantID).Find(&requests)
	return requests, result.Error
}

// GetInterviewRequestsByRecruiter retrieves all interview requests created by a specific recruiter
func GetInterviewRequestsByRecruiter(recruiterID string) ([]InterviewRequest, error) {
	var requests []InterviewRequest
	result := db.Where("recruiter_id = ?", recruiterID).Find(&requests)
	return requests, result.Error
}

// UpdateInterviewRequestStatus updates the status of an interview request
func UpdateInterviewRequestStatus(requestID, status string) error {
	return db.Model(&InterviewRequest{}).Where("id = ?", requestID).Update("status", status).Error
}