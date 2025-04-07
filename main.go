package main



import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"github.com/google/uuid"


)

// Replace with your credentials
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
	sessions = make(map[string]string) // sessionID -> userID
	users    = make(map[string]User)   // userID -> User
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

	// If user doesn't exist, register them as an Applicant by default
	if _, exists := users[id]; !exists {
		role := RoleApplicant
		approved := true
	
		// Make yourself Super Admin
		if email == "raghav.uj@gmail.com" {
			role = RoleSuperAdmin
		}
		users[id] = User{
			ID:       id,
			Email:    email,
			Name:     name,
			Role:     role, // default role
			Approved: approved,
		}
	}

	// Generate a session ID
	sessionID := uuid.New().String()
	sessions[sessionID] = id

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:  "session",
		Value: sessionID,
		Path:  "/",
	})

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
func handleDashboard(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	userID := sessions[cookie.Value]
	user, exists := users[userID]
	if !exists {
		http.Redirect(w, r, "/", http.StatusSeeOther)
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
    sessionCookie, err := r.Cookie("session")
    if err != nil {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    userID, ok := sessions[sessionCookie.Value]
    if !ok {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    user := users[userID]
    if user.Role != RoleSuperAdmin {
        http.Error(w, "Access denied", http.StatusForbidden)
        return
    }

    // List unapproved recruiters
    html := "<h2>Pending Recruiter Approvals</h2>"
    for _, u := range users {
        if u.Role == RoleRecruiter && !u.Approved {
            html += fmt.Sprintf(`<p>%s (%s) 
                <a href="/approve?uid=%s">[Approve]</a></p>`, u.Name, u.Email, u.ID)
        }
    }

    html += `<br><a href="/dashboard">Back to Dashboard</a>`

    fmt.Fprint(w, html)
}
func handleApproveRecruiter(w http.ResponseWriter, r *http.Request) {
    sessionCookie, err := r.Cookie("session")
    if err != nil {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    userID, ok := sessions[sessionCookie.Value]
    if !ok {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    currentUser := users[userID]
    if currentUser.Role != RoleSuperAdmin {
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

