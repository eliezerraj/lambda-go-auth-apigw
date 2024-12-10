package apigw

import(
	"context"
	"strings"
	"github.com/rs/zerolog/log"

	"github.com/aws/aws-lambda-go/events"

	"github.com/lambda-go-auth-apigw/internal/erro"
	"github.com/lambda-go-auth-apigw/internal/usecase/certs"
	"github.com/lambda-go-auth-apigw/internal/usecase/policy"
	"github.com/lambda-go-auth-apigw/internal/usecase/jwt"
	"github.com/lambda-go-auth-apigw/internal/model"
)

var childLogger = log.With().Str("handler", "apigw").Logger()

var policyData model.PolicyData
var res_validation bool
var err error

type LambdaHandler struct {
    usecaseCerts certs.UseCaseCerts
	usecasePolicy policy.UseCasePolicy
	usecaseJwt jwt.UseCaseJwt
	isTokenRSA bool
}

func InitializeLambdaHandler(	usecaseCerts certs.UseCaseCerts,
								usecasePolicy policy.UseCasePolicy,
								usecaseJwt jwt.UseCaseJwt,
								isTokenRSA bool) *LambdaHandler {
	childLogger.Debug().Msg("InitializeLambdaHandler")

    return &LambdaHandler{
        usecaseCerts: usecaseCerts,
		usecasePolicy: usecasePolicy,
		usecaseJwt: usecaseJwt,
		isTokenRSA: isTokenRSA,
    }
}

func (h *LambdaHandler) LambdaHandlerRequest(ctx context.Context, request events.APIGatewayCustomAuthorizerRequestTypeRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	childLogger.Debug().Msg("lambdaHandlerRequest")
	
	policyData.Effect = "Deny"
	policyData.PrincipalID = "NA-PrincipalID"
	policyData.Message = "Unauthorized"

	if(false){
		h.usecaseCerts.VerifyCertCRL(ctx, request.RequestContext.Identity.ClientCert.ClientCertPem)
	}
	
	bearerToken, err := bearerTokenValidation(request)
	if err != nil {
		switch err {
		case erro.ErrArnMalFormad:
			policyData.Message = "token validation - arn invalid"
		case erro.ErrBearTokenFormad:
			policyData.Message = "token validation - beared token invalid"
		default:
			policyData.Message = "token validation"
		}
	}

	if h.isTokenRSA {
		res_validation, err = h.usecaseJwt.TokenValidationRSA(ctx, *bearerToken)
	}else {
		res_validation, err = h.usecaseJwt.TokenValidation(ctx, *bearerToken)
	}
	//res_validation, err := h.usecaseJwt.TokenValidation(ctx, *bearerToken)
	if err != nil {
		switch err {
		case erro.ErrStatusUnauthorized:
			policyData.Message = "Failed ScopeValidation - Signature Invalid"
		case erro.ErrTokenExpired:
			policyData.Message = "Failed ScopeValidation - Token Expired/Invalid"
		default:
			policyData.Message = "Failed ScopeValidation"
		}
	}

	log.Debug().Interface("res_validation : ", res_validation ).Msg("")

	if res_validation {
		policyData.Effect = "Allow"
		policyData.Message = "Authorized"
	}

	res := h.usecasePolicy.GeneratePolicyFromClaims(ctx, policyData)
	return res, nil
}

func bearerTokenValidation(request events.APIGatewayCustomAuthorizerRequestTypeRequest) (*string, error){
	childLogger.Debug().Msg("bearerTokenValidation")

	//Check the size of arn
	if (len(request.MethodArn) < 6 || request.MethodArn == ""){
		log.Error().Str("request.MethodArn size error : ", string(rune(len(request.MethodArn)))).Msg("")
		return nil, erro.ErrArnMalFormad
	}

	//Parse the method and path
	arn := strings.SplitN(request.MethodArn, "/", 4)
	method := arn[2]
	path := arn[3]

	log.Debug().Interface("method : ", method).Msg("")
	log.Debug().Interface("path : ", path).Msg("")

	//Extract the token from header
	var token string
	if (request.Headers["Authorization"] != "")  {
		token = request.Headers["Authorization"]
	} else if (request.Headers["authorization"] != "") {
		token = request.Headers["authorization"]
	}

	var bearerToken string
	tokenSlice := strings.Split(token, " ")
	if len(tokenSlice) > 1 {
		bearerToken = tokenSlice[len(tokenSlice)-1]
	} else {
		bearerToken = token
	}

	if len(bearerToken) < 1 {
		log.Error().Msg("Empty Token")
		return nil, erro.ErrBearTokenFormad
	}

	return &bearerToken, nil
}