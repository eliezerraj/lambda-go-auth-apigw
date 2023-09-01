package service

import (
	"strings"

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

func (a AuthService) ScopeValidation(credential domain.Credential, path string, method string) (bool, error){
	childLogger.Debug().Msg("ScopeValidation")
	log.Debug().Str("path", path ).Msg("++")
	log.Debug().Str("method", method).Msg("++")

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

	log.Debug().Interface("claims.Scope : ", claims.Scope).Msg("++")
	isValidPath := false

	for _, scopeListItem := range claims.Scope {
		isValidPath = false

		scopeSlice := strings.Split(scopeListItem, ".")
		// In this case is ANY allowed method, just check the scope(path) itself
		if len(scopeSlice) == 1 {
			if path == "admin" {
				log.Debug().Msg("++++++++++ TRUE ADMIN ++++++++++++++++++")
				return true ,nil
			}
			if strings.Contains(path, "/" + scopeSlice[0]) {
				log.Debug().Msg("++++++++++ TRUE 1 ++++++++++++++++++")
				return true ,nil
			}
		} else {
			// In this case it would check the method and the scope(path)
			for _, scopeItem := range scopeSlice {
				log.Debug().Interface("=====>  scopeItem :", scopeItem).Msg(" <=====")

				if strings.Contains(path, "/" + scopeItem) {
					log.Debug().Msg("++++++++++ TRUE 2.1 ++++++++++++++++++")
					log.Debug().Str(path, scopeItem ).Msg(" ")
					isValidPath = true
					continue 
				}
				if isValidPath == true {
					log.Debug().Msg("++++++++++ TRUE 2.2 ++++++++++++++++++")
					log.Debug().Str(method, scopeItem ).Msg(" ")
					if method == "ANY" {
						return true ,nil
					}
					if method == "GET" && scopeItem == "read" {
						return true ,nil
					}
					if method == "POST" && scopeItem == "write" {
						return true ,nil
					}
					if method == "PUT" && scopeItem == "write" {
						return true ,nil
					}
					if method == "PATCH" && scopeItem == "update" {
						return true ,nil
					}
					if method == "DELETE" && scopeItem == "delete" {
						return true ,nil
					}
				}
			}
		}
	}
	return false ,nil
}
