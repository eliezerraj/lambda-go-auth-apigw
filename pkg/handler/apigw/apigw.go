package apigw

import(
	"context"
	"strings"
	"github.com/rs/zerolog/log"

	"github.com/aws/aws-lambda-go/events"
	"github.com/lambda-go-auth-apigw/pkg/observability"

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
	isCRLValidation bool
	isScopeValidation bool
}

func InitializeLambdaHandler(	usecaseCerts certs.UseCaseCerts,
								usecasePolicy policy.UseCasePolicy,
								usecaseJwt jwt.UseCaseJwt,
								isTokenRSA bool,
								isCRLValidation bool,
								isScopeValidation bool) *LambdaHandler {
	childLogger.Debug().Msg("InitializeLambdaHandler")

    return &LambdaHandler{
        usecaseCerts: usecaseCerts,
		usecasePolicy: usecasePolicy,
		usecaseJwt: usecaseJwt,
		isTokenRSA: isTokenRSA,
		isCRLValidation: isCRLValidation,
		isScopeValidation: isScopeValidation,
    }
}

func (h *LambdaHandler) LambdaHandlerRequest(ctx context.Context, request events.APIGatewayCustomAuthorizerRequestTypeRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	childLogger.Debug().Msg("lambdaHandlerRequest")
	
	span := observability.Span(ctx, "handler.LambdaHandlerRequest")	
    defer span.End()

	policyData.Effect = "Deny"
	policyData.PrincipalID = "go-authorizer-principalID"
	policyData.Message = "unauthorized"
	policyData.MethodArn = request.MethodArn
	claims := &model.JwtData{}

	//token structure
	bearerToken, err := TokenStructureValidation(ctx, request)
	if err != nil{
		switch err {
		case erro.ErrArnMalFormad:
			policyData.Message = "token validation - arn invalid"
		case erro.ErrBearTokenFormad:
			policyData.Message = "token validation - beared token invalid"
		default:
			policyData.Message = "token validation"
		}
		return h.usecasePolicy.GeneratePolicyFromClaims(ctx, policyData), nil
	}

	//token cert validation
	if h.isTokenRSA {
		res_validation, claims, err = h.usecaseJwt.TokenValidationRSA(ctx, bearerToken)
	}else {
		res_validation, claims, err = h.usecaseJwt.TokenValidation(ctx, bearerToken)
	}
	if err != nil {
		switch err {
		case erro.ErrStatusUnauthorized:
			policyData.Message = "failed scope validation - signature invalid"
		case erro.ErrTokenExpired:
			policyData.Message = "failed scope validation - token expired/invalid"
		default:
			policyData.Message = "failed scope validation"
		}
		return h.usecasePolicy.GeneratePolicyFromClaims(ctx, policyData), nil
	}

	//CRL
	if(h.isCRLValidation){
		log.Debug().Interface("ClientCert.ClientCertPem : ", request.RequestContext.Identity.ClientCert.ClientCertPem).Msg("")

		res_crl, err := h.usecaseCerts.VerifyCertCRL(ctx, request.RequestContext.Identity.ClientCert.ClientCertPem)
		if err != nil || !res_crl{
			policyData.Message = "unauthorized cert revoked"
		}
		return h.usecasePolicy.GeneratePolicyFromClaims(ctx, policyData), nil
	}

	// Scope
	if (h.isScopeValidation) {
		// Check the JWT signed and scope
		res_validation = h.ScopeValidation(ctx, *claims, request.MethodArn)
		if !res_validation {
			policyData.Message = "unauthorized by token validation"
			return h.usecasePolicy.GeneratePolicyFromClaims(ctx, policyData), nil
		} 
	}

	policyData.Effect = "Allow"
	policyData.Message = "Authorized"

	res := h.usecasePolicy.GeneratePolicyFromClaims(ctx, policyData)

	// Add authorization context data
	res = h.usecasePolicy.InsertDataAuthorizationContext(ctx, claims.JwtId ,res)

	return res, nil
}

func TokenStructureValidation(ctx context.Context, request events.APIGatewayCustomAuthorizerRequestTypeRequest) (*string, error){
	childLogger.Debug().Msg("TokenStructureValidation")

	span := observability.Span(ctx, "handler.tokenStructureValidation")	
    defer span.End()

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

func (l *LambdaHandler) ScopeValidation(ctx context.Context, claims model.JwtData, arn string) (bool){
	childLogger.Debug().Msg("ScopeValidation")

	span := observability.Span(ctx, "handler.ScopeValidation")	
    defer span.End()

	log.Debug().Str("arn: ", arn ).Msg("")

	res_arn := strings.SplitN(arn, "/", 4)
	method := res_arn[2]
	path := res_arn[3]

	log.Debug().Str("method", method).Msg("")
	log.Debug().Interface("claims", claims).Msg("")

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
				return true
			}
			// if the path is equal scope, ex: info (informed) is equal info (scope)
			if strings.Contains(path, scopeSlice[0]) {
				log.Debug().Msg("++++++++++ NO ADMIN BUT SCOPE ANY ++++++++++++++++++")
				return true
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
					return true
				} else if 	(method == "GET" && methodScope == "read" ) || 
							(method == "POST" && methodScope == "write" ) ||
							(method == "PUT" && methodScope == "write") ||
							(method == "PATCH" && methodScope == "update") ||
							(method == "DELETE" && methodScope == "delete"){
					log.Debug().Msg("ALLOWED - Methods equals !!!")
					return true
				} 
			}
		}
	}

	log.Debug().Msg("SCOPE informed not found !!!")
	
	return false
}