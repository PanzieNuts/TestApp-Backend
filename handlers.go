package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

var (
	clientID     = "1093697499477113"
	clientSecret = "991bb5caa3fa46549b2995a6f0f594e2"
	redirectURI = "http://localhost:8080/api/auth/facebook/callback"
)

type FacebookTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type FacebookUser struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

func FacebookLoginHandler(w http.ResponseWriter, r *http.Request) {
	fbURL := fmt.Sprintf(
		"https://www.facebook.com/v19.0/dialog/oauth?client_id=%s&redirect_uri=%s&scope=email",
		clientID, url.QueryEscape(redirectURI),
	)
	http.Redirect(w, r, fbURL, http.StatusTemporaryRedirect)
}

func FacebookCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing code in callback", http.StatusBadRequest)
		return
	}

	// Exchange code for access token
	tokenURL := fmt.Sprintf(
		"https://graph.facebook.com/v19.0/oauth/access_token?client_id=%s&redirect_uri=%s&client_secret=%s&code=%s",
		clientID, url.QueryEscape(redirectURI), clientSecret, code,
	)

	resp, err := http.Get(tokenURL)
	if err != nil {
		http.Error(w, "Failed to get access token", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read token response", http.StatusInternalServerError)
		return
	}

	var tokenData FacebookTokenResponse
	if err := json.Unmarshal(body, &tokenData); err != nil {
		http.Error(w, "Failed to parse token response", http.StatusInternalServerError)
		return
	}

	// Get user info
	userResp, err := http.Get("https://graph.facebook.com/me?fields=id,name,email&access_token=" + tokenData.AccessToken)
	if err != nil {
		http.Error(w, "Failed to fetch user info", http.StatusInternalServerError)
		return
	}
	defer userResp.Body.Close()

	userBody, err := io.ReadAll(userResp.Body)
	if err != nil {
		http.Error(w, "Failed to read user response", http.StatusInternalServerError)
		return
	}

	var fbUser FacebookUser
	if err := json.Unmarshal(userBody, &fbUser); err != nil {
		http.Error(w, "Failed to parse user response", http.StatusInternalServerError)
		return
	}

	// Store user in DB or find existing one
	user, err := FindOrCreateUser(fbUser.ID, fbUser.Name, fbUser.Email)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	jwtToken, err := GenerateJWT(user.ID)
	if err != nil {
		http.Error(w, "Failed to generate JWT", http.StatusInternalServerError)
		return
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    jwtToken,
		HttpOnly: true,
		Secure:   false,
		Path:     "/",
	})

	http.Redirect(w, r, "http://localhost:3000/home?login=facebook", http.StatusSeeOther)
}
