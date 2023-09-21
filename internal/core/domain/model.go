package domain

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type Credential struct {
	Token	string `json:"token,omitempty"`
}

type JwtData struct {
	Username	string 		`json:"username"`
	Scope		[]string 	`json:"scope"`
	jwt.RegisteredClaims
}

type UserProfile struct {
	ID				string	`json:"id,omitempty"`
	SK				string	`json:"sk,omitempty"`
	TenantID		string	`json:"tenant_id,omitempty"`
	Updated_at  	time.Time 	`json:"updated_at,omitempty"`
}
