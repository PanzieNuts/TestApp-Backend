package main

import (
	"log"
	"net/http"
)

func main() {
	InitDB()

	http.HandleFunc("/api/auth/facebook", FacebookLoginHandler)
	http.HandleFunc("/api/auth/facebook/callback", FacebookCallbackHandler)

	log.Println("Server running at :8080")
	http.ListenAndServe(":8080", nil)
}
