package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	
	
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

func withCORS(handler http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        enableCORS(w)
        if r.Method == http.MethodOptions {
            w.WriteHeader(http.StatusOK)
            return
        }
        handler(w, r)
    }
}


func FacebookLoginHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Redirect user to Facebook OAuth dialog
	fbURL := fmt.Sprintf(
		"https://www.facebook.com/v19.0/dialog/oauth?client_id=%s&redirect_uri=%s&scope=email",
		clientID, url.QueryEscape(redirectURI),
	)
	http.Redirect(w, r, fbURL, http.StatusTemporaryRedirect)
}

func FacebookCallbackHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Check if user canceled (Facebook sends error and error_description query params on cancel)
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		// Redirect to login page on cancel or error
		http.Redirect(w, r, "http://localhost:3000/login", http.StatusSeeOther)
		return
	}

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

	// Get user info from Facebook graph API
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

	// Find or create user in DB
	user, err := FindOrCreateUser(fbUser.ID, fbUser.Name, fbUser.Email)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Generate JWT token
	jwtToken, err := GenerateJWT(user.ID)
	if err != nil {
		http.Error(w, "Failed to generate JWT", http.StatusInternalServerError)
		return
	}

	// Set JWT in HttpOnly cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    jwtToken,
		HttpOnly: true,
		Path:     "/",
		// Secure: true, // set true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect to frontend home page after login
	http.Redirect(w, r, "http://localhost:3000/home?login=facebook", http.StatusSeeOther)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Clear cookie to log out
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
		// Secure: true, for production
		Secure: false,
	})

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Logged out"))
}

// AuthMiddleware validates the JWT token cookie and logs out user on failure
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil || cookie.Value == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token, _, err := ValidateJWT(cookie.Value)
		if err != nil || !token.Valid {
			// Clear cookie on invalid token to force logout
			http.SetCookie(w, &http.Cookie{
				Name:     "session_token",
				Value:    "",
				Path:     "/",
				HttpOnly: true,
				MaxAge:   -1,
				SameSite: http.SameSiteLaxMode,
				Secure: true,
			})

			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
}
