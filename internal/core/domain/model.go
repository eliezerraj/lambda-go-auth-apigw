package domain

import (

	"github.com/golang-jwt/jwt/v4"
)

type Credential struct {
	Token			string `json:"token,omitempty"`
}

type JwtData struct {
	Username	string 	`json:"username"`
	Scope		[]string 	`json:"scope"`
	jwt.RegisteredClaims
}