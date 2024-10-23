package service

import (
	"testing"
	"context"
	"github.com/rs/zerolog"

	"github.com/lambda-go-auth-apigw/internal/core"
	"github.com/lambda-go-auth-apigw/internal/repository"
)

var (
	logLevel		= zerolog.DebugLevel // InfoLevel DebugLevel
	authService		*AuthService
	tableName		= "user-login-2"
	jwtKey			= "my-secret-key"
	credential 		= core.Credential{Token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJpc3MiOiJsYW1iZGEtZ28tYXV0ZW50aWNhdGlvbiIsInZlcnNpb24iOiIyIiwiand0X2lkIjoiYzg3ZTQyYTAtMTZkZi00MGU1LWI1OTYtZDdhODdmYjQ2ZGY1IiwidXNlcm5hbWUiOiJhZG1pbiIsInNjb3BlIjpbImFkbWluIl0sImV4cCI6MTcyODkxMTQ2Nn0.gHrINj9qfVaeqm47AOHDjIZTriZX0Z93mRXowXRqKa8" }
)

func TestTokenValidation(t *testing.T) {
	zerolog.SetGlobalLevel(logLevel)

	authRepository, err := repository.NewAuthRepository(context.TODO(),tableName)
	if err != nil {
		t.Errorf("configuration error AuthRepository() %v ",err.Error())
	}

	authService = NewAuthService([]byte(jwtKey), authRepository)
	_, token, err := authService.TokenValidation(context.TODO(), credential)
	if err != nil {
		t.Errorf("Error -TokenValidation Erro: %v ", err)
	}

	if token {
		t.Logf("Success TokenValidation token" )
	} else {
		t.Errorf("Failed TokenValidation")
	}
}

func TestScopeValidation(t *testing.T) {
	zerolog.SetGlobalLevel(logLevel)

	path := "info"
	method := "POST"
	
	authRepository, err := repository.NewAuthRepository(context.TODO(), tableName)
	if err != nil {
		t.Errorf("configuration error AuthRepository() %v ",err.Error())
	}

	authService = NewAuthService([]byte(jwtKey),authRepository)
	_ ,token, err := authService.ScopeValidation(context.TODO(), credential, path, method)
	if err != nil {
		t.Errorf("Error -TestScopeValidation Erro %v ", err)
	}

	if token {
		t.Logf("Success TestScopeValidation" )
	} else {
		t.Errorf("Failed TestScopeValidation")
	}
}