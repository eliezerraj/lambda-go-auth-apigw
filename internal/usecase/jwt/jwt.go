package jwt

import (
	"fmt"
	"context"
	"crypto/x509"
	"crypto/rsa"
    "encoding/pem"

	"github.com/golang-jwt/jwt/v4"

	"github.com/rs/zerolog/log"

	"github.com/lambda-go-auth-apigw/pkg/observability"
	"github.com/lambda-go-auth-apigw/internal/erro"
	"github.com/lambda-go-auth-apigw/internal/model"
)

var childLogger = log.With().Str("useCase", "jwt").Logger()

type UseCaseJwt struct{
	rsaKey 					*model.RSA_Key
}

func NewUseCaseJwt(	ctx context.Context,
					rsaKey *model.RSA_Key) (*UseCaseJwt, error){

	childLogger.Debug().Msg("NewUseCaseJwt")

	_key_rsa_priv, err := ParsePemToRSAPriv(&rsaKey.Key_rsa_priv_pem)
	if err != nil{
		childLogger.Error().Err(err).Msg("erro ParsePemToRSA !!!!")
	}
	_key_rsa_pub, err := ParsePemToRSAPub(&rsaKey.Key_rsa_pub_pem)
	if err != nil{
		childLogger.Error().Err(err).Msg("erro ParsePemToRSA !!!!")
	}

	rsaKey.Key_rsa_priv = _key_rsa_priv
	rsaKey.Key_rsa_pub = _key_rsa_pub

	return &UseCaseJwt{
		rsaKey:	rsaKey,
	}, nil
}

func ParsePemToRSAPriv(private_key *string) (*rsa.PrivateKey, error){
	childLogger.Debug().Msg("ParsePemToRSA")

	block, _ := pem.Decode([]byte(*private_key))
	if block == nil || block.Type != "PRIVATE KEY" {
		childLogger.Error().Err(erro.ErrDecodeKey).Msg("erro Decode")
		return nil, erro.ErrDecodeKey
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		childLogger.Error().Err(err).Msg("erro ParsePKCS8PrivateKey")
		return nil, err
	}

	key_rsa := privateKey.(*rsa.PrivateKey)

	return key_rsa, nil
}

func ParsePemToRSAPub(public_key *string) (*rsa.PublicKey, error){
	childLogger.Debug().Msg("ParsePemToRSA")

	block, _ := pem.Decode([]byte(*public_key))
	if block == nil || block.Type != "PUBLIC KEY" {
		childLogger.Error().Err(erro.ErrDecodeKey).Msg("erro Decode")
		return nil, erro.ErrDecodeKey
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		childLogger.Error().Err(err).Msg("erro ParsePKCS8PrivateKey")
		return nil, err
	}

	key_rsa := pubInterface.(*rsa.PublicKey)

	return key_rsa, nil
}

func (u *UseCaseJwt) TokenValidationRSA(ctx context.Context, bearerToken string) (bool, error){
	childLogger.Debug().Msg("TokenValidationRSA")
	childLogger.Debug().Interface("=> bearerToken : ", bearerToken).Msg("")
	childLogger.Debug().Msg("--------------------------------------")

	span := observability.Span(ctx, "usecase.TokenValidationRSA")
	defer span.End()

	// Check with token is signed 
	claims := &model.JwtData{}
	tkn, err := jwt.ParseWithClaims(bearerToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("error unexpected signing method: %v", token.Header["alg"])
		}
		return u.rsaKey.Key_rsa_pub, nil
	})

	if err != nil {
		fmt.Println(err)
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

func (u *UseCaseJwt) TokenValidation(ctx context.Context, bearerToken string) (bool, error){
	childLogger.Debug().Msg("TokenValidation")
	childLogger.Debug().Interface("=> bearerToken : ", bearerToken).Msg("")
	childLogger.Debug().Msg("--------------------------------------")

	span := observability.Span(ctx, "usecase.TokenValidation")
	defer span.End()

	// Check with token is signed 
	claims := &model.JwtData{}
	tkn, err := jwt.ParseWithClaims(bearerToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(u.rsaKey.JwtKey), nil
	})

	if err != nil {
		fmt.Println(err)
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