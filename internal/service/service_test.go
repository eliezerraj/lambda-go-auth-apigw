package service


import (
	"testing"
	"github.com/rs/zerolog"

	"github.com/lambda-go-auth-apigw/internal/core/domain"

)

var (
	logLevel		= zerolog.DebugLevel // InfoLevel DebugLevel
	authService		*AuthService
)

func TestTokenValidation(t *testing.T) {
	zerolog.SetGlobalLevel(logLevel)
	jwtKey	:= "my_secret_key"
	credential := domain.Credential{Token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjAwNyIsInNjb3BlIjpbImluZm8ucmVhZCIsImEucmVhZCIsInN1bS53cml0ZSIsInZlcnNpb24iLCJoZWFkZXIucmVhZCJdLCJleHAiOjE2OTM1MDgzNjZ9.mh8mTSO95-Kzb0kHR0oUrQ7-LMovgjf8oflQrfFDIZA" }

	authService = NewAuthService([]byte(jwtKey))
	token, err := authService.TokenValidation(credential)
	if err != nil {
		t.Errorf("Error -TokenValidation Erro %v ", err)
	}

	if (token == true) {
		t.Logf("Success TokenValidation token" )
	} else {
		t.Errorf("Failed TokenValidation")
	}
}

func TestScopeValidation(t *testing.T) {
	zerolog.SetGlobalLevel(logLevel)
	jwtKey	:= "my_secret_key"
	path := "/pod-a/a"
	method := "POST"

	credential := domain.Credential{Token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjAwNyIsInNjb3BlIjpbImluZm8ucmVhZCIsImEucmVhZCIsInN1bS53cml0ZSIsInZlcnNpb24iLCJoZWFkZXIucmVhZCJdLCJleHAiOjE2OTM1MDgzNjZ9.mh8mTSO95-Kzb0kHR0oUrQ7-LMovgjf8oflQrfFDIZA" }

	authService = NewAuthService([]byte(jwtKey))
	token, err := authService.ScopeValidation(credential, path, method)
	if err != nil {
		t.Errorf("Error -TestScopeValidation Erro %v ", err)
	}

	if (token == true) {
		t.Logf("Success TestScopeValidation" )
	} else {
		t.Errorf("Failed TestScopeValidation")
	}
}