package main

type User struct {
	ID          int    `json:"id"`
	FacebookID  string `json:"facebook_id"`
	Name        string `json:"name"`
	Email       string `json:"email"`
}
