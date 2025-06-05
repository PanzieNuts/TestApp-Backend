package main

import (
	"log"
	"os"
	"net/http"
	"github.com/joho/godotenv" 
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	clientID = os.Getenv("CLIENT_ID")
	clientSecret = os.Getenv("CLIENT_SECRET")
	redirectURI = os.Getenv("REDIRECT_URI")
}


func main() {
	InitDB()

	http.HandleFunc("/api/auth/facebook", FacebookLoginHandler)
	http.HandleFunc("/api/auth/facebook/callback", FacebookCallbackHandler)
	http.HandleFunc("/api/logout", LogoutHandler)

	// Example protected route
	http.HandleFunc("/api/protected", AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("You are authenticated"))
	}))

	log.Println("Server running at :8080")
	http.ListenAndServe(":8080", nil)
}


func enableCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}


