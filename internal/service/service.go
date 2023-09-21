package service

import (
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/lambda-go-auth-apigw/internal/core/domain"
	"github.com/lambda-go-auth-apigw/internal/repository"
	"github.com/lambda-go-auth-apigw/internal/erro"
	"github.com/golang-jwt/jwt/v4"
)

var childLogger = log.With().Str("service", "AuthService").Logger()

type AuthService struct {
	jwtKey	[]byte
	authRepository	*repository.AuthRepository
}

func NewAuthService(jwtKey []byte,
					authRepository *repository.AuthRepository ) *AuthService{
	childLogger.Debug().Msg("NewAuthService")
	return &AuthService{
		jwtKey: jwtKey,
		authRepository: authRepository,
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

	// Check the JWT signature
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

	// Valid the scope in a naive way
	isValidPath := false
	for _, scopeListItem := range claims.Scope {
		isValidPath = false

		scopeSlice := strings.Split(scopeListItem, ".")

		// In this case when just method informed it means the all methods are allowed (ANY)
		// Ex: path (info) or (admin)
		if len(scopeSlice) == 1 {
			if path == "admin" {
				log.Debug().Msg("++++++++++ TRUE ADMIN ++++++++++++++++++")
				return true ,nil
			}
			if strings.Contains(path, "/" + scopeSlice[0]) {
				log.Debug().Msg("++++++++++ NO ADMIN ++++++++++++++++++")
				return true ,nil
			}
		} else {
			// In this case it would check the method and the scope(path)
			// Ex: path/scope (version.read)
			for _, scopeItem := range scopeSlice {
				log.Debug().Interface("=====>  scopeItem :", scopeItem).Msg(" <=====")

				if strings.Contains(path, "/" + scopeItem) {
					log.Debug().Str(path, scopeItem ).Msg(" ")
					isValidPath = true
					continue 
				}
				if isValidPath == true {
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

func (a AuthService) LoadUserProfile(user domain.UserProfile) (*domain.UserProfile, error) {
	childLogger.Debug().Msg("LoadUserProfile")
	
	userProfile, err := a.authRepository.LoadUserProfile(user)
	if err != nil {
		return nil, err
	}

	return userProfile, nil
}

func (a AuthService) ExtractClaims(credential domain.Credential) (*domain.JwtData, error){
	childLogger.Debug().Msg("ExtractClaims")

	claims := &domain.JwtData{}
	tkn, err := jwt.ParseWithClaims(credential.Token, claims, func(token *jwt.Token) (interface{}, error) {
		return a.jwtKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, erro.ErrStatusUnauthorized
		}
		return nil, erro.ErrTokenExpired
	}

	if !tkn.Valid {
		return nil, erro.ErrStatusUnauthorized
	}

	return claims ,nil
}