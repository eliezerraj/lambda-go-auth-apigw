package service

import (
	"fmt"
	"strings"
	"context"
	"crypto/x509"
	"github.com/rs/zerolog/log"
	
	"github.com/aws/aws-lambda-go/events"

	"github.com/lambda-go-auth-apigw/internal/config/observability"
	"github.com/lambda-go-auth-apigw/internal/core"
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

func (a AuthService) TokenValidation(ctx context.Context, credential core.Credential) (*core.JwtData, bool, error){
	childLogger.Debug().Msg("TokenValidation")

	span := observability.Span(ctx, "service.tokenValidation")	
    defer span.End()

	claims := &core.JwtData{}
	tkn, err := jwt.ParseWithClaims(credential.Token, claims, func(token *jwt.Token) (interface{}, error) {
		return a.jwtKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, false, erro.ErrStatusUnauthorized
		}
		return nil, false, erro.ErrTokenExpired
	}

	if !tkn.Valid {
		return nil, false, erro.ErrStatusUnauthorized
	}

	return claims, true ,nil
}

func (a AuthService) ScopeValidation(ctx context.Context, credential core.Credential, path string, method string) (*core.JwtData, bool, error){
	childLogger.Debug().Msg("ScopeValidation")

	log.Debug().Str("path", path ).Msg("")
	log.Debug().Str("method", method).Msg("")
	log.Debug().Interface("credential", credential).Msg("")

	span := observability.Span(ctx, "service.scopeValidation")	
    defer span.End()

	// Check the JWT signature
	claims := &core.JwtData{}
	tkn, err := jwt.ParseWithClaims(credential.Token, claims, func(token *jwt.Token) (interface{}, error) {
		return a.jwtKey, nil
	})
	
	log.Debug().Interface("+++> claims : ", claims).Msg("")

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return claims, false, erro.ErrStatusUnauthorized
		}
		return claims,false, erro.ErrTokenExpired
	}
	if !tkn.Valid {
		return claims,false, erro.ErrStatusUnauthorized
	}

	// Valid the scope in a naive way
	var pathScope, methodScope string
	for _, scopeListItem := range claims.Scope {
		// Split ex: versiom.read in 2 parts
		scopeSlice := strings.Split(scopeListItem, ".")
		pathScope = scopeSlice[0]
		
		// In this case when just method informed it means the all methods are allowed (ANY)
		// Ex: path (info) or (admin)
		// if lenght is 1, means only the path was given
		if len(scopeSlice) == 1 {
			if pathScope == "admin" {
				log.Debug().Msg("++++++++++ TRUE ADMIN ++++++++++++++++++")
				return claims, true ,nil
			}
			// if the path is equal scope, ex: info (informed) is equal info (scope)
			if strings.Contains(path, scopeSlice[0]) {
				log.Debug().Msg("++++++++++ NO ADMIN BUT SCOPE ANY ++++++++++++++++++")
				return claims, true ,nil
			}
		// both was given path + method
		} else {
			// In this case it would check the method and the scope(path)
			// Ex: path/scope (version.read)
			log.Debug().Interface("scopeListItem....", scopeListItem).Msg("")

			methodScope = scopeSlice[1]

			if pathScope == path {
				log.Debug().Msg("PASS - Paths equals !!!")
				if method == "ANY" {
					log.Debug().Msg("ALLOWED - method ANY!!!")
					return claims, true ,nil
				} else if 	(method == "GET" && methodScope == "read" ) || 
							(method == "POST" && methodScope == "write" ) ||
							(method == "PUT" && methodScope == "write") ||
							(method == "PATCH" && methodScope == "update") ||
							(method == "DELETE" && methodScope == "delete"){
					log.Debug().Msg("ALLOWED - Methods equals !!!")
					return claims, true ,nil
				} 
			}
		}
	}

	log.Debug().Msg("SCOPE informed not found !!!!")
	
	return claims, false ,nil
}

func (a AuthService) LoadUserProfile(ctx context.Context, user core.UserProfile) (*core.UserProfile, error) {
	childLogger.Debug().Msg("LoadUserProfile")

	span := observability.Span(ctx, "service.loadUserProfile")	
    defer span.End()

	userProfile, err := a.authRepository.LoadUserProfile(ctx, user)
	if err != nil {
		return nil, err
	}

	return userProfile, nil
}

func(a AuthService) VerifyCertCRL(	ctx context.Context,
									crl []byte, 
									cacert *x509.Certificate) (bool, error){
	childLogger.Debug().Msg("VerifyCertCRL")

	span := observability.Span(ctx, "service.verifyCertCRL")	
    defer span.End()

	certSerialNumber := cacert.SerialNumber
	fmt.Println(certSerialNumber)

	_crl, err := x509.ParseCRL(crl)
	if err != nil {
		return false, err
	}

	for _, revokedCert := range _crl.TBSCertList.RevokedCertificates {
		if revokedCert.SerialNumber.Cmp(certSerialNumber) == 0 {
			return true, nil
		}
	}

	fmt.Println(cacert.SerialNumber)
	return false, nil
}

func(a AuthService) GeneratePolicyFromClaims(ctx context.Context, policyData core.PolicyData) events.APIGatewayCustomAuthorizerResponse {
	childLogger.Debug().Msg("GeneratePolicyFromClaims")
	
	span := observability.Span(ctx, "service.GeneratePolicyFromClaims")	
    defer span.End()

	// Create a policy
	authResponse := events.APIGatewayCustomAuthorizerResponse{PrincipalID: policyData.JwtData.Username}
	authResponse.PolicyDocument = events.APIGatewayCustomAuthorizerPolicy{
		Version: "2012-10-17",
		Statement: []events.IAMPolicyStatement{
			{
				Action:   []string{"execute-api:Invoke"},
				Effect:   policyData.Effect,
				Resource: []string{policyData.MethodArn},
			},
		},
	}
	
	authResponse.Context = make(map[string]interface{})
	authResponse.Context["authMessage"] = policyData.Message
	authResponse.Context["jwtId"] = policyData.JwtData.JwtId

	userProfile := core.UserProfile{ID: policyData.JwtData.Username}
	res_userProfile, _ := a.authRepository.LoadUserProfile(ctx, userProfile)
	if res_userProfile != nil {
		authResponse.Context["tenantId"] = res_userProfile.TenantID
	}

	return authResponse
}
