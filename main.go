package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"io"
	"net/http"
	"strings"
	"net/smtp"
	"os"
	"github.com/joho/godotenv"
	"github.com/ledongthuc/pdf"
	"path/filepath"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"bytes"
)

var googleOauthConfig = &oauth2.Config{
	RedirectURL:  "http://localhost:8080/callback",
	ClientID:     "572516427547-lgupc32c56c9bbj6vc433pl72r2n53ac.apps.googleusercontent.com",
	ClientSecret: "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",
	Scopes:       []string{"https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"},
	Endpoint:     google.Endpoint,
}

var oauthStateString = "randomstatestring"

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println(" Warning: .env file not loaded, using defaults")
	}
	
	initDB()
	http.HandleFunc("/", handleMain)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleGoogleCallback)
	http.HandleFunc("/recruiter-info", handleRecruiterInfo)
	http.HandleFunc("/applicant/upload-cv", handleUploadCV)
	http.HandleFunc("/superadmin/dashboard", handleSuperAdminDashboard)
	http.HandleFunc("/admin", handleAdminDashboard)
	http.HandleFunc("/approve", handleApproveRecruiter)
	http.HandleFunc("/dashboard", handleDashboard)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/applicant/jobs", handleApplicantJobs)
	http.HandleFunc("/recruiter/view-applicants", handleViewApplicantsForJob)
	http.HandleFunc("/recruiter/schedule", handleScheduleInterview)
	http.HandleFunc("/follow-company", handleFollowCompany)

	// Start server
	fmt.Println("✅ Server starting at http://localhost:8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleMain(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `
		<!DOCTYPE html>
		<html>
		<head>
			<title>Login</title>
		</head>
		<body>
			<h2>Welcome to the Job Portal</h2>
			<a href="/login">Sign In with Google</a>
		</body>
		</html>
	`)
}


func handleLogin(w http.ResponseWriter, r *http.Request) {
	url := googleOauthConfig.AuthCodeURL(oauthStateString)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}


var (
	sessions = make(map[string]User)
	users    = make(map[string]User)
	jobs     = make(map[string]Job)
	jobApplications = make(map[string][]string) 
	interviewRequests = make(map[string]InterviewRequest)
	companyFollowers = make(map[string][]string) 
)



func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	client := googleOauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		http.Error(w, "Failed to get user info: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var userInfo map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&userInfo)

	id := userInfo["id"].(string)
	email := userInfo["email"].(string)
	name := userInfo["name"].(string)

	// Create user if not exists
	if _, exists := users[id]; !exists {
		var role string
		var approved bool
		var company *Company

		switch email {
		case "raghav.uj@gmail.com":
			role = RoleSuperAdmin
			approved = true

		default:
			// Assume applicant by default
			role = RoleApplicant
			approved = true
		}

		// Recruiter logic (email or pattern based)
		if email == "mosd472@gmail.com" || strings.Contains(email, "recruit") {
			role = RoleRecruiter
			approved = false
			company = nil
			name = "Recruiter"
		}

		users[id] = User{
			ID:       id,
			Email:    email,
			Name:     name,
			Role:     role,
			Approved: approved,
			Company:  company,
		}
	}

	// ✅ Create session
	sessionID := uuid.New().String()
	sessions[sessionID] = users[id]

	http.SetCookie(w, &http.Cookie{
		Name:  "session",
		Value: sessionID,
		Path:  "/",
	})

	// 🚦 Redirect logic
	user := users[id]
	if user.Role == RoleRecruiter && !user.Approved {
		http.Redirect(w, r, "/recruiter-info", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}


func handleDashboard(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromSession(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 🔁 Always refresh user from the users map
	if latest, exists := users[user.ID]; exists {
		user = latest
		sessions[getSessionID(r)] = latest // Sync session with latest user
	}

	fmt.Println("DEBUG: Recruiter session check →", user.Email, "| Approved:", user.Approved)

	// 🚦 Role-based redirection
	switch user.Role {
	case RoleSuperAdmin:
		http.Redirect(w, r, "/superadmin/dashboard", http.StatusSeeOther)

	case RoleRecruiter:
		if !user.Approved {
			fmt.Fprint(w, `<html><body><p>Your recruiter account is pending approval by a Super Admin.</p></body></html>`)
			return
		}
		http.Redirect(w, r, "/recruiter/dashboard", http.StatusSeeOther)

	case RoleApplicant:
		http.Redirect(w, r, "/applicant/jobs", http.StatusSeeOther)

	default:
		http.Error(w, "Invalid role", http.StatusForbidden)
	}
}
func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		delete(sessions, cookie.Value)
		http.SetCookie(w, &http.Cookie{
			Name:   "session",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromSession(r)
	if !ok || user.Role != RoleSuperAdmin {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	fmt.Fprint(w, `<html><head><title>Admin Dashboard</title></head><body>`)
	defer fmt.Fprint(w, `</body></html>`)

	fmt.Fprint(w, `<h2>Pending Recruiter Approvals</h2>`)
	for _, u := range users {
		if u.Role == RoleRecruiter && !u.Approved {
			fmt.Fprintf(w, `<p>Recruiter (%s) 
                <a href="/approve?uid=%s">[Approve]</a></p><br>`, u.Email, u.ID)
		}
	}
	fmt.Fprint(w, `<br><a href="/superadmin/dashboard">Back to Admin Home</a>`)

}


func getUserFromSession(r *http.Request) (User, bool) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return User{}, false
	}

	sessionID := cookie.Value
	user, ok := sessions[sessionID]
	if ok {
		return user, true
	}

	// 💡 Dev fallback (not for production!)
	// Try finding user by ID in cookie (if you saved it in value), or skip fallback
	fmt.Println("⚠️ Session not found for ID:", sessionID)
	return User{}, false
}
func handleApproveRecruiter(w http.ResponseWriter, r *http.Request) {
	// Get Super Admin's session
	sessionCookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	adminUser, ok := sessions[sessionCookie.Value]
	if !ok || adminUser.Role != RoleSuperAdmin {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	// Get recruiter ID to approve
	recruiterID := r.URL.Query().Get("uid")
	recruiter, exists := users[recruiterID]
	if exists && recruiter.Role == RoleRecruiter {
		// ✅ Update approval status
		recruiter.Approved = true
		users[recruiterID] = recruiter

		// ✅ Update recruiter in all active sessions
		for sid, sessUser := range sessions {
			if sessUser.ID == recruiterID {
				sessions[sid] = recruiter
				fmt.Println("✅ Session updated for:", recruiter.Email)
				fmt.Println("DEBUG: Final recruiter in sessions →", sessions[sid].Approved)
			}
		}
	} else {
		fmt.Println("⚠️ Recruiter not found or invalid role for ID:", recruiterID)
	}

	// ✅ Redirect back to admin dashboard
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}


func handleAdmin(w http.ResponseWriter, r *http.Request) {
	_, ok := getUserFromSession(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	fmt.Fprint(w, `<html><head><title>Admin Panel</title></head><body>`)
	defer fmt.Fprint(w, `</body></html>`)

	fmt.Fprintln(w, `<h2>Recruiters Pending Approval</h2><br>`)
	for id, u := range users {
		if u.Role == RoleRecruiter && !u.Approved {
			fmt.Fprintf(w, `Name: %s, Email: %s - <a href="/approve?id=%s">Approve</a><br>`, u.Name, u.Email, id)
		}
	}
}


func handleApprove(w http.ResponseWriter, r *http.Request) {
	_, ok := getUserFromSession(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	fmt.Fprint(w, `<html><head><title>Approval Status</title></head><body>`)
	defer fmt.Fprint(w, `</body></html>`)

	id := r.URL.Query().Get("id")
	recruiter, exists := users[id]
	if exists && recruiter.Role == RoleRecruiter {
		recruiter.Approved = true
		users[id] = recruiter
		fmt.Fprintf(w, "<p>✅ Approved recruiter: %s</p>", recruiter.Email)
	} else {
		fmt.Fprint(w, "<p>❌ Invalid recruiter ID</p>")
	}

	fmt.Fprint(w, `<br><a href="/admin">Back to Admin Dashboard</a>`)
}


func handleRecruiterInfo(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromSession(r)
	if !ok || user.Role != RoleRecruiter {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	// Already has company info
	if user.Company != nil {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodGet {
		// ✅ Wrap form in proper HTML
		fmt.Fprint(w, `<html><head><title>Company Info</title></head><body>`)
		defer fmt.Fprint(w, `</body></html>`)

		fmt.Fprint(w, `
			<h2>Enter Company Details</h2>
			<form method="POST">
				<label>Company Name:</label><br>
				<input type="text" name="name" required><br><br>

				<label>Description:</label><br>
				<textarea name="description" required></textarea><br><br>

				<label>Logo URL:</label><br>
				<input type="text" name="logo" required><br><br>

				<input type="submit" value="Submit">
			</form>
		`)
	} else if r.Method == http.MethodPost {
		// ✅ Process form data
		name := r.FormValue("name")
		description := r.FormValue("description")
		logo := r.FormValue("logo")

		company := &Company{
			Name:        name,
			Description: description,
			LogoURL:     logo,
			Approved:    false, // Super Admin will approve
		}

		// Update the user's company details
		updatedUser := user
		updatedUser.Company = company
		users[user.ID] = updatedUser
		sessions[getSessionID(r)] = updatedUser

		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}


func getSessionID(r *http.Request) string {
	cookie, err := r.Cookie("session")
	if err != nil {
		return ""
	}
	return cookie.Value
}
func handleRecruiterDashboard(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromSession(r)
	if !ok {
		fmt.Println("⚠️ Recruiter dashboard: no session found")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	fmt.Println("✅ Recruiter dashboard loaded for:", user.Email, "Approved:", user.Approved)

	if user.Role != RoleRecruiter {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}
	if !user.Approved {
		http.Error(w, "You are not approved yet", http.StatusForbidden)
		return
	}

	fmt.Fprint(w, `<html><head><title>Recruiter Dashboard</title></head><body>`)
	defer fmt.Fprint(w, `</body></html>`)

	fmt.Fprintf(w, `<h2>Recruiter Dashboard</h2>`)
	fmt.Fprintf(w, `<p>Welcome, %s (%s)</p>`, user.Name, user.Email)

	// Link to post a new job
	fmt.Fprintf(w, `<a href="/recruiter/post-job">Post a New Job</a><br><br>`)

	// Link to search applicants
	fmt.Fprintf(w, `<a href="/recruiter/search">Search Applicants by Skill</a><br><br>`)

	// Show posted jobs
	fmt.Fprintf(w, `<h3>Your Job Postings</h3>`)
	found := false
	for _, job := range jobs {
		if job.PostedByID == user.ID {
			found = true
			fmt.Fprintf(w, `<p><b>%s</b><br>%s<br>Skills: %v</p>`, job.Title, job.Description, job.Skills)
		}
	}
	if !found {
		fmt.Fprint(w, `<p>No jobs posted yet.</p>`)
	}
}

func handlePostJob(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromSession(r)
	if !ok || user.Role != RoleRecruiter || !user.Approved {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method == http.MethodGet {
		fmt.Fprint(w, `<html><head><title>Post a Job</title></head><body>`)
		defer fmt.Fprint(w, `</body></html>`)

		fmt.Fprint(w, `
			<h2>Post a Job</h2>
			<form method="POST">
				<label>Job Title:</label><br>
				<input type="text" name="title" required><br><br>

				<label>Description:</label><br>
				<textarea name="description" required></textarea><br><br>

				<label>Skills (comma-separated):</label><br>
				<input type="text" name="skills" required><br><br>

				<input type="submit" value="Post Job">
			</form>
		`)
	} else if r.Method == http.MethodPost {
		title := r.FormValue("title")
		description := r.FormValue("description")
		skillStr := r.FormValue("skills")
		skills := parseSkills(skillStr)

		job := Job{
			ID:          uuid.New().String(),
			Title:       title,
			Description: description,
			Skills:      skills,
			CompanyID:   user.ID, // assuming 1 recruiter = 1 company
			PostedByID:    user.ID,
		}

		jobs[job.ID] = job

		http.Redirect(w, r, "/recruiter/dashboard", http.StatusSeeOther)
	}
}


func parseSkills(s string) []string {
	var result []string
	for _, skill := range strings.Split(s, ",") {
		result = append(result, strings.TrimSpace(skill))
	}
	return result
}
func handleApplicantJobs(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromSession(r)
	if !ok || user.Role != RoleApplicant {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	fmt.Fprint(w, `<html><head><title>Available Jobs</title></head><body>`)
	defer fmt.Fprint(w, `</body></html>`)

	fmt.Fprint(w, `<h2>Available Jobs</h2>`)

	for jobID, job := range jobs {
		// Check if job is posted by an approved recruiter
		recruiter, ok := users[job.PostedByID]
		if !ok || !recruiter.Approved {
			continue
		}

		// Match applicant skills
		matched := false
		for _, skill := range job.Skills {
			for _, applicantSkill := range user.Skills {
				if strings.EqualFold(skill, applicantSkill) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			continue
		}

		// Check if already applied
		applied := false
		for _, applicantID := range jobApplications[jobID] {
			if applicantID == user.ID {
				applied = true
				break
			}
		}

		// Render job block
		companyName := ""
if recruiter.Company != nil {
	companyName = recruiter.Company.Name
}

fmt.Fprintf(w, `<div><b>%s</b><br>%s<br>Skills: %v<br>`, job.Title, job.Description, job.Skills)

if applied {
	fmt.Fprint(w, `<i>Already Applied</i><br>`)
} else {
	fmt.Fprintf(w, `
		<form action="/applicant/apply" method="POST" style="display:inline;">
			<input type="hidden" name="job_id" value="%s">
			<input type="submit" value="Apply">
		</form><br>`, jobID)
}

if companyName != "" {
	fmt.Fprintf(w, `
		<form action="/follow-company" method="POST">
			<input type="hidden" name="company" value="%s">
			<input type="submit" value="Follow %s">
		</form>`, companyName, companyName)
}

fmt.Fprint(w, `</div><hr>`)

		if applied {
			fmt.Fprint(w, `<i>Already Applied</i>`)
		} else {
			fmt.Fprintf(w, `
				<form action="/applicant/apply" method="POST">
					<input type="hidden" name="job_id" value="%s">
					<input type="submit" value="Apply">
				</form>`, jobID)
		}
		fmt.Fprint(w, `</div><hr>`)
	}
}
func handleViewApplicantsForJob(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromSession(r)
	if !ok || user.Role != RoleRecruiter || !user.Approved {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	jobID := r.URL.Query().Get("jobid")
	job, exists := jobs[jobID]
	if !exists || job.PostedByID != user.ID {
		http.Error(w, "Job not found or unauthorized", http.StatusForbidden)
		return
	}

	fmt.Fprintf(w, `<html><head><title>Applicants</title></head><body>`)
	fmt.Fprintf(w, `<h2>Applicants for Job: %s</h2>`, job.Title)

	applicants := jobApplications[jobID]
	if len(applicants) == 0 {
		fmt.Fprint(w, `<p>No applicants yet.</p>`)
	} else {
		for _, applicantID := range applicants {
			applicant := users[applicantID]
			fmt.Fprintf(w, `<div style="border:1px solid #ccc; padding:10px; margin:10px;">
				<p><b>Name:</b> %s<br><b>Email:</b> %s</p>`, applicant.Name, applicant.Email)

			if applicant.Resume != "" {
				fmt.Fprintf(w, `
					<form method="POST" action="/recruiter/parse-resume">
						<input type="hidden" name="applicant_id" value="%s">
						<input type="submit" value="Parse Resume">
					</form>`, applicant.ID)
			} else {
				fmt.Fprint(w, `<i>No resume uploaded</i>`)
			}
			fmt.Fprint(w, `</div>`)
		}
	}

	fmt.Fprint(w, `<br><a href="/recruiter/dashboard">Back to Dashboard</a></body></html>`)
}
func handleScheduleInterview(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromSession(r)
	if !ok || user.Role != RoleRecruiter || !user.Approved {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method == http.MethodGet {
		fmt.Fprint(w, `<html><head><title>Schedule Interview</title></head><body>`)
		defer fmt.Fprint(w, `</body></html>`)

		fmt.Fprint(w, `<h2>Schedule Interview</h2>
			<form method="POST">
			<label>Select Job:</label><br>
			<select name="job_id">`)
		for _, job := range jobs {
			if job.PostedByID == user.ID {
				fmt.Fprintf(w, `<option value="%s">%s</option>`, job.ID, job.Title)
			}
		}
		fmt.Fprint(w, `</select><br><br>`)

		fmt.Fprint(w, `<label>Applicant Email:</label><br>
			<input type="email" name="applicant_email" required><br><br>
			<label>Proposed Time:</label><br>
			<input type="text" name="time" placeholder="e.g. April 10, 4:00 PM" required><br><br>
			<input type="submit" value="Send Interview Request">
			</form>`)
	} else if r.Method == http.MethodPost {
		applicantEmail := r.FormValue("applicant_email")
		proposedTime := r.FormValue("time")
		jobID := r.FormValue("job_id")

		// Lookup applicant
		var applicantID string
		for _, u := range users {
			if u.Email == applicantEmail && u.Role == RoleApplicant {
				applicantID = u.ID
				break
			}
		}
		if applicantID == "" {
			http.Error(w, "Applicant not found", http.StatusBadRequest)
			return
		}

		interview := InterviewRequest{
			ID:           uuid.New().String(),
			JobID:        jobID,
			ApplicantID:  applicantID,
			RecruiterID:  user.ID,
			Status:       "pending",
			ProposedTime: proposedTime,
			MeetLink:     "https://meet.google.com/" + uuid.New().String()[:8],
		}

		interviewRequests[interview.ID] = interview

		// Send interview email asynchronously
		go sendEmail(users[applicantID].Email,
			"Interview Invitation",
			fmt.Sprintf("You have been invited for an interview on: %s\nMeet Link: %s", proposedTime, interview.MeetLink))

		http.Redirect(w, r, "/recruiter/dashboard", http.StatusSeeOther)
	}
}
func sendEmail(to, subject, body string) {
	from := os.Getenv("SMTP_EMAIL")
	pass := os.Getenv("SMTP_PASSWORD")
	auth := smtp.PlainAuth("", from, pass, "smtp.gmail.com")

	msg := []byte("To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n\r\n" +
		body + "\r\n")

	err := smtp.SendMail("smtp.gmail.com:587", auth, from, []string{to}, msg)
	if err != nil {
		log.Printf("❌ Failed to send email to %s: %v", to, err)
	} else {
		log.Printf("✅ Email sent to %s", to)
	}
}

func handleUploadCV(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromSession(r)
	if !ok || user.Role != RoleApplicant {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method == http.MethodGet {
		fmt.Fprint(w, `<html><head><title>Upload CV</title></head><body>`)
		defer fmt.Fprint(w, `</body></html>`)
		fmt.Fprint(w, `
			<h2>Upload Resume (PDF)</h2>
			<form method="POST" enctype="multipart/form-data">
				<input type="file" name="resume" accept="application/pdf" required><br><br>
				<input type="submit" value="Upload CV">
			</form>
		`)
		return
	}

	// Handle file upload
	file, handler, err := r.FormFile("resume")
	if err != nil {
		http.Error(w, "Failed to read file: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Save uploaded file temporarily
	filePath := filepath.Join("uploads", user.ID+"_"+handler.Filename)
	os.MkdirAll("uploads", os.ModePerm)
	dst, err := os.Create(filePath)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()
	io.Copy(dst, file)

	// Parse and validate PDF
	f, rErr := os.Open(filePath)
	if rErr != nil {
		http.Error(w, "Failed to open uploaded file", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	reader, err := pdf.NewReader(f, handler.Size)
	if err != nil {
		http.Error(w, "Failed to parse PDF: "+err.Error(), http.StatusInternalServerError)
		return
	}
	textReader, _ := reader.GetPlainText()
	buf := new(strings.Builder)
	io.Copy(buf, textReader)
	content := strings.ToLower(buf.String())


	// Validate for keywords
	if !strings.Contains(content, "name") ||
		!strings.Contains(content, "skills") ||
		!strings.Contains(content, "education") {
		http.Error(w, "Incomplete resume: must include Name, Skills, and Education.", http.StatusBadRequest)
		return
	}

	// Save resume path to user
	updated := user
	updated.Resume = filePath
	users[user.ID] = updated
	sessions[getSessionID(r)] = updated

	fmt.Fprint(w, `<html><body><p>✅ Resume uploaded successfully!</p><a href="/dashboard">Back to Dashboard</a></body></html>`)
}

func parseResumeWithGemini(text string) (string, error) {
	apiKey := os.Getenv("GEMINI_API_KEY")
	url := "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=" + apiKey

	reqBody := map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"parts": []map[string]string{
					{
						"text": "You're an expert recruiter. Summarize this resume into Name, Education, Experience, Skills, and a brief 2-line profile summary:\n\n" + text,
					},
				},
			},
		},
	}

	jsonData, _ := json.Marshal(reqBody)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return "", err
	}

	if len(result.Candidates) > 0 && len(result.Candidates[0].Content.Parts) > 0 {
		return result.Candidates[0].Content.Parts[0].Text, nil
	}
	return "No response from Gemini", nil
}
func handleFollowCompany(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromSession(r)
	if !ok || user.Role != RoleApplicant {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	company := r.FormValue("company")
	if company == "" {
		http.Error(w, "Company not specified", http.StatusBadRequest)
		return
	}

	// Prevent duplicate follow
	followers := companyFollowers[company]
	for _, id := range followers {
		if id == user.ID {
			http.Redirect(w, r, "/applicant/jobs", http.StatusSeeOther)
			return
		}
	}

	// Add follower
	companyFollowers[company] = append(companyFollowers[company], user.ID)

	http.Redirect(w, r, "/applicant/jobs", http.StatusSeeOther)
}
func handleSuperAdminDashboard(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromSession(r)
	if !ok || user.Role != RoleSuperAdmin {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Dashboard page
	fmt.Fprint(w, `<html><head><title>Super Admin Dashboard</title></head><body>`)
	defer fmt.Fprint(w, `</body></html>`)

	fmt.Fprintf(w, `<h2>Welcome, %s (Super Admin)</h2>`, user.Name)

	// Admin links
	fmt.Fprint(w, `
		<ul>
			<li><a href="/admin">Pending Recruiter Approvals</a></li>
			<li><a href="/logout">Logout</a></li>
		</ul>
	`)
}






