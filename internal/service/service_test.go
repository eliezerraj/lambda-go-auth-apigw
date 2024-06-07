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
	tableName		= "user-login"
	jwtKey			= "my_secret_key"
	credential 		= domain.Credential{Token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwic2NvcGUiOlsiYWRtaW4iXSwiZXhwIjoxNzA0MjUwMjM1fQ.v_XgHEKiyVeueYQWUzIbPUnbAK_DdhDVr4dgx4vaJK8" }
)

func TestTokenValidation(t *testing.T) {
	zerolog.SetGlobalLevel(logLevel)

	authRepository, err := repository.NewAuthRepository(tableName)
	if err != nil {
		t.Errorf("configuration error AuthRepository() %v ",err.Error())
	}

	authService = NewAuthService([]byte(jwtKey), authRepository)
	token, err := authService.TokenValidation(context.TODO(), credential)
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

	path := "info"
	method := "POST"
	
	authRepository, err := repository.NewAuthRepository(tableName)
	if err != nil {
		t.Errorf("configuration error AuthRepository() %v ",err.Error())
	}

	authService = NewAuthService([]byte(jwtKey),authRepository)
	_ ,token, err := authService.ScopeValidation(context.TODO(), credential, path, method)
	if err != nil {
		t.Errorf("Error -TestScopeValidation Erro %v ", err)
	}

	if (token == true) {
		t.Logf("Success TestScopeValidation" )
	} else {
		t.Errorf("Failed TestScopeValidation")
	}
}