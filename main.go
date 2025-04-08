package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
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
	http.HandleFunc("/", handleMain)
	http.HandleFunc("/login", handleLogin)

	http.HandleFunc("/callback", handleGoogleCallback)
	http.HandleFunc("/recruiter-info", handleRecruiterInfo)

	http.HandleFunc("/admin", handleAdminDashboard)
	http.HandleFunc("/approve", handleApproveRecruiter)

	http.HandleFunc("/dashboard", handleDashboard)
	http.HandleFunc("/logout", handleLogout)

	


	fmt.Println("Server starting at http://localhost:8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleMain(w http.ResponseWriter, r *http.Request) {
	html := `<html><body>
	<a href="/login">Sign In with Google</a>
	</body></html>`
	fmt.Fprint(w, html)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	url := googleOauthConfig.AuthCodeURL(oauthStateString)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

var (
	sessions = make(map[string]User)
	users    = make(map[string]User)
	jobs  []Job
)

type Role string

const (
	RoleSuperAdmin Role = "superadmin"
	RoleRecruiter  Role = "recruiter"
	RoleApplicant  Role = "applicant"
)

type User struct {
	ID       string
	Email    string
	Name     string
	Role     Role
	Approved bool
	Company *Company
}

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

	if _, exists := users[id]; !exists {
		var role Role
		var approved bool
		var company *Company

		switch email {
		case "raghav.uj@gmail.com":
			role = RoleSuperAdmin
			approved = true

		case "mosd472@gmail.com":
			role = RoleRecruiter
			approved = false
			company = nil

			users[id] = User{
				ID:       id,
				Email:    email,
				Name:     "Recruiter",
				Role:     role,
				Approved: approved,
				Company:  company,
			}

			sessionID := uuid.New().String()
			sessions[sessionID] = users[id]
			http.SetCookie(w, &http.Cookie{
				Name:  "session",
				Value: sessionID,
				Path:  "/",
			})

			http.Redirect(w, r, "/recruiter-info", http.StatusSeeOther)
			return

		default:
			role = RoleApplicant
			approved = true
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

	sessionID := uuid.New().String()
	sessions[sessionID] = users[id]

	http.SetCookie(w, &http.Cookie{
		Name:  "session",
		Value: sessionID,
		Path:  "/",
	})

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromSession(r)
if !ok {
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
	return
}

	
	if user.Role == RoleRecruiter && !user.Approved {
		fmt.Fprint(w, "Your recruiter account is pending approval by a Super Admin.")
		return
	}

	fmt.Fprintf(w, "Welcome %s! Your role is: %s<br><br><a href=\"/logout\">Logout</a>", user.Name, user.Role)
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

	fmt.Fprint(w, `<h2>Pending Recruiter Approvals</h2>`)
	for _, u := range users {
		if u.Role == RoleRecruiter && !u.Approved {
			fmt.Fprintf(w, `<p>Recruiter (%s) 
                <a href="/approve?uid=%s">[Approve]</a></p><br>`, u.Email, u.ID)
		}
	}
	fmt.Fprint(w, `<a href="/dashboard">Back to Dashboard</a>`)
}

func getUserFromSession(r *http.Request) (User, bool) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return User{}, false
	}

	userID, ok := sessions[cookie.Value]
	if !ok {
		return User{}, false
	}

	user, ok := users[userID.ID]
	if !ok {
		return User{}, false
	}

	return user, true
}



func handleApproveRecruiter(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	user, ok := sessions[sessionCookie.Value]
	if !ok || user.Role != RoleSuperAdmin {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	recruiterID := r.URL.Query().Get("uid")
	if recruiter, exists := users[recruiterID]; exists && recruiter.Role == RoleRecruiter {
		recruiter.Approved = true
		users[recruiterID] = recruiter
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
func handleAdmin(w http.ResponseWriter, r *http.Request) {
	_, ok := getUserFromSession(r)
if !ok {
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
	return
}

	

	fmt.Fprintln(w, "Recruiters pending approval:<br><br>")
	for id, u := range users {
		if u.Role == RoleRecruiter && !u.Approved {
			fmt.Fprintf(w, "Name: %s, Email: %s - <a href=\"/approve?id=%s\">Approve</a><br>", u.Name, u.Email, id)
		}
	}
}

func handleApprove(w http.ResponseWriter, r *http.Request) {
	_, ok := getUserFromSession(r)
if !ok {
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
	return
}

	

	id := r.URL.Query().Get("id")
	recruiter, exists := users[id]
	if exists && recruiter.Role == RoleRecruiter {
		recruiter.Approved = true
		users[id] = recruiter
		fmt.Fprintf(w, "Approved recruiter: %s", recruiter.Email)
	} else {
		fmt.Fprint(w, "Invalid recruiter ID")
	}
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
		// Show the form
		fmt.Fprintf(w, `
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
		// 💡 Here’s the important POST handler logic
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
type Company struct {
	Name        string
	Description string
	LogoURL     string
	Approved    bool
}
type Job struct {
	ID          string
	Title       string
	Description string
	Skills      []string
	CompanyID   string
	PostedBy    string // Recruiter ID
}

type Applicant struct {
	ID       string
	Name     string
	Email    string
	Skills   []string
	Resume   string
}

type InterviewRequest struct {
	ID          string
	JobID       string
	ApplicantID string
	Status      string // pending, accepted, rejected
}
func handleRecruiterDashboard(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromSession(r)
	if !ok || user.Role != RoleRecruiter || !user.Approved {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

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
		if job.PostedBy == user.ID {
			found = true
			fmt.Fprintf(w, `<p><b>%s</b><br>%s<br>Skills: %v</p>`, job.Title, job.Description, job.Skills)
		}
	}
	if !found {
		fmt.Fprint(w, "No jobs posted yet.")
	}
}




