package main

import (
	"database/sql"
	"log"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB

func InitDB() {
	var err error
	db, err = sql.Open("mysql", "root:admin@tcp(127.0.0.1:3306)/login")
	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}
}

func FindOrCreateUser(facebookID, name, email string) (*User, error) {
	var user User

	err := db.QueryRow("SELECT id, facebook_id, name, email FROM users WHERE facebook_id = ?", facebookID).
		Scan(&user.ID, &user.FacebookID, &user.Name, &user.Email)

	if err == sql.ErrNoRows {
		res, err := db.Exec("INSERT INTO users (facebook_id, name, email) VALUES (?, ?, ?)", facebookID, name, email)
		if err != nil {
			return nil, err
		}
		lastID, _ := res.LastInsertId()
		user = User{ID: int(lastID), FacebookID: facebookID, Name: name, Email: email}
		return &user, nil
	}

	if err != nil {
		return nil, err
	}

	return &user, nil
}
