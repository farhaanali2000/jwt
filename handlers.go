package main

import (
	"encoding/json"
	// "go/token"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var jwtKey = []byte("secret-key")

var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

type Claims struct {
	Username string `json: "username"`
	jwt.StandardClaims
}

type Credentials struct {
	Username string `json: "username"`
	Password string `json: "password"`
}

func Login(w http.ResponseWriter, r *http.Request) {
	var Credentials Credentials
	err := json.NewDecoder(r.Body).Decode(&Credentials)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expectedPassword, ok := users[Credentials.Username]

	if !ok || expectedPassword != Credentials.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	expirationtime := time.Now().Add(time.Minute * 5)

	claims := &Claims{
		Username: Credentials.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationtime.Unix(),
		},
	}

	//using claims and jwt secret key to generate a tokenstring
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w,
		&http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expirationtime,
		},
	)

}

func Home(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tokenStr := cookie.Value
	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tokenStr, claims,
		func(t *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
	}

	w.Write([]byte(fmt.Sprintf("Hello, %s", claims.Username)))

}

func Refresh(w http.ResponseWriter, r *http.Request) {

}
