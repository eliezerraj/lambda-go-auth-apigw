package service

import (
	"github.com/rs/zerolog/log"

	"github.com/lambda-go-auth-apigw/internal/core/domain"
	"github.com/lambda-go-auth-apigw/internal/erro"
	"github.com/golang-jwt/jwt/v4"
)

var childLogger = log.With().Str("service", "AuthService").Logger()

type AuthService struct {
	jwtKey	[]byte
}

func NewAuthService( jwtKey []byte ) *AuthService{
	childLogger.Debug().Msg("NewAuthService")
	return &AuthService{
		jwtKey: jwtKey,
	}
}

func (a AuthService) TokenValidation(credential domain.Credential) (bool, error){
	childLogger.Debug().Msg("TokenValidation")

	claims := &domain.JwtData{}
	tkn, err := jwt.ParseWithClaims(credential.Token, claims, func(token *jwt.Token) (interface{}, error) {
		return a.jwtKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return false, erro.ErrStatusUnauthorized
		}
		return false, erro.ErrTokenExpired
	}

	if !tkn.Valid {
		return false, erro.ErrStatusUnauthorized
	}

	return true ,nil
}