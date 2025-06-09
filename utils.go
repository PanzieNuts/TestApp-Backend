package main

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtKey = []byte("your-secret")

type Claims struct {
	UserID int `json:"user_id"`
	jwt.RegisteredClaims
}

func GenerateJWT(userID int) (string, time.Time, error) {
    // Load Manila timezone
    loc, err := time.LoadLocation("Asia/Manila")
    if err != nil {
        loc = time.UTC // fallback to UTC if error
    }

    // Current time in Manila timezone
    now := time.Now().In(loc)

    // Set expiration 1 minute from now (Manila time)
    expiresAt := now.Add(1 * time.Minute)

    claims := &Claims{
        UserID: userID,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(expiresAt),
            IssuedAt:  jwt.NewNumericDate(now),
            Issuer:    "TestApp",
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenStr, err := token.SignedString(jwtKey)
    return tokenStr, expiresAt, err
}


func ValidateJWT(tokenStr string) (*jwt.Token, *Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("unexpected signing method")
		}
		return jwtKey, nil
	})

	if err != nil {
		return nil, nil, err
	}

	if !token.Valid {
		return nil, nil, errors.New("invalid token")
	}

	return token, claims, nil
}
