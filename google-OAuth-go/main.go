package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
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
	http.HandleFunc("/callback", handleCallback)

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

func handleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if state != oauthStateString {
		http.Error(w, "State mismatch", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Code exchange failed", http.StatusInternalServerError)
		return
	}

	resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var userInfo map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&userInfo)

	fmt.Fprintf(w, "User Info: %+v", userInfo)
}
