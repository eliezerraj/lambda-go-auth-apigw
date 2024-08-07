package main

import(
	"context"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/lambda-go-auth-apigw/internal/service"
	"github.com/lambda-go-auth-apigw/internal/repository"
	"github.com/lambda-go-auth-apigw/internal/config/observability"
	"github.com/lambda-go-auth-apigw/internal/core"
	"github.com/lambda-go-auth-apigw/internal/erro"
	"github.com/lambda-go-auth-apigw/internal/util"
	"github.com/lambda-go-auth-apigw/internal/config/config_aws"
	"github.com/lambda-go-auth-apigw/internal/config/parameter_store_aws"
	"github.com/lambda-go-auth-apigw/internal/config/bucket_s3_aws"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"

	"go.opentelemetry.io/contrib/propagators/aws/xray"
	"go.opentelemetry.io/otel"
 	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-lambda-go/otellambda"
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-lambda-go/otellambda/xrayconfig"
	"go.opentelemetry.io/otel/trace"
)

var (
	logLevel	=	zerolog.DebugLevel // InfoLevel DebugLevel
	authService	*service.AuthService
	appServer	core.AppServer
	load_crl_pem	*[]byte
	tracer 			trace.Tracer
)

func init() {
	log.Debug().Msg("init")
	zerolog.SetGlobalLevel(logLevel)
	appServer = util.GetAppInfo()
	configOTEL := util.GetOtelEnv()
	appServer.ConfigOTEL = &configOTEL
}

func main() {
	log.Debug().Msg("main")
	log.Debug().Interface("appServer : ", appServer).Msg(".")

	// set config
	ctx := context.Background()
	awsConfig, err := config_aws.GetAWSConfig(ctx)
	if err != nil {
		panic("configuration error create new aws session " + err.Error())
	}

	// Get Parameter-Store
	clientSsm := parameter_store_aws.NewClientParameterStore(*awsConfig)
	jwtKey, err := clientSsm.GetParameter(ctx, appServer.InfoApp.SSMJwtKey)
	if err != nil {
		panic("Error GetParameter " + err.Error())
	}
	log.Debug().Str("======== > jwtKey", *jwtKey).Msg("")

	// Create a repository
	authRepository, err := repository.NewAuthRepository(appServer.InfoApp.TableName, *awsConfig)
	if err != nil {
		panic("configuration error AuthRepository(), " + err.Error())
	}

	// Load the CRL
	if appServer.InfoApp.CrlValidation == true {
		log.Debug().Msg("Loading CRL cert form S3")
		clientS3 := bucket_s3_aws.NewClientS3Bucket(*awsConfig)
		load_crl_pem, err = clientS3.GetObject(ctx, 
												appServer.InfoApp.CrlBucketNameKey,
												appServer.InfoApp.CrlFilePath,
												appServer.InfoApp.CrlFileKey)
		if err != nil {
			log.Error().Err(err).Msg("Erro LoadKeyAsFileS3")
		}
	}

	// Create a service
	authService = service.NewAuthService([]byte(*jwtKey), authRepository)
		
	//----- OTEL ----//
	tp := observability.NewTracerProvider(ctx, appServer.ConfigOTEL, appServer.InfoApp)
	defer func(ctx context.Context) {
			err := tp.Shutdown(ctx)
			if err != nil {
				log.Error().Err(err).Msg("Error shutting down tracer provider")
			}
	}(ctx)
	
	otel.SetTextMapPropagator(xray.Propagator{})
	otel.SetTracerProvider(tp)
	
	tracer = tp.Tracer("lambda-go-auth-apigw-tracer")
	lambda.Start(otellambda.InstrumentHandler(lambdaHandlerRequest, xrayconfig.WithRecommendedOptions(tp)... ))
}

// Integration APIGW as Request (USED)
// When use lambda authorizer type Request
func lambdaHandlerRequest(ctx context.Context, request events.APIGatewayCustomAuthorizerRequestTypeRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	log.Debug().Msg("lambdaHandlerRequest")
	log.Debug().Msg("-------------------")
	log.Debug().Interface("request : ", request).Msg("")

	ctx, span := tracer.Start(ctx, "lambdaHandlerRequest")
    defer span.End()

	var response bool
	var err error
	var policyData core.PolicyData
 	claims := &core.JwtData{ Username: ""}

	policyData.Effect = "Deny"
	policyData.JwtData = claims
	policyData.Message = "Unauthorized"
	
	//--------------------------- Check CRL
	if appServer.InfoApp.CrlValidation == true {
		CertX509PemDecoded := request.RequestContext.Identity.ClientCert.ClientCertPem
		log.Debug().Interface("Client CertX509PemDecoded : ", CertX509PemDecoded).Msg("")
		
		// The cert must be informed
		if CertX509PemDecoded == ""{
			log.Info().Msg("Client Cert no Informed !!!")
			policyData.Message = "Unauthorized Certificate not Informed !!!!"
			return authService.GeneratePolicyFromClaims(ctx, policyData), nil
		}
		
		certX509, err := util.ParsePemToCertx509(CertX509PemDecoded)
		if err != nil {
			log.Debug().Msg("Erro ParsePemToCertx509!!!")
		}
		response_crl, err := authService.VerifyCertCRL(ctx, *load_crl_pem, certX509)
		if err != nil {
			log.Debug().Msg("Unauthorized Cert Revoked !!!")
			policyData.Message = "Unauthorized Cert Revoked !!!"
			return authService.GeneratePolicyFromClaims(ctx, policyData), nil
		}
		log.Debug().Interface(" ====> CrlValidation response : ", response_crl).Msg("")
		// response_crl is true means the cert is revoked
		if response_crl == true {
			policyData.Message = "Unauthorized Certificate revoked !!!"
			return authService.GeneratePolicyFromClaims(ctx, policyData), nil
		}
	}
	//-------------------------------- Check the size of arn
	if (len(request.MethodArn) < 6 || request.MethodArn == ""){
		log.Debug().Str("request.MethodArn size error : ", string(len(request.MethodArn))).Msg("")
		policyData.Message = "Unauthorized ARN mal-formed !!!"
		return authService.GeneratePolicyFromClaims(ctx, policyData), nil
	}
	policyData.MethodArn = request.MethodArn
	//-------------------- Parse the method and path
	arn := strings.SplitN(request.MethodArn, "/", 4)
	method := arn[2]
	path := arn[3]

	log.Debug().Interface("method : ", method).Msg("")
	log.Debug().Interface("path : ", path).Msg("")

	//------------------- Extract the token from header
	var token string
	if (request.Headers["Authorization"] != "")  {
		token = request.Headers["Authorization"]
	} else if (request.Headers["authorization"] != "") {
		token = request.Headers["authorization"]
	}
	log.Debug().Str("token : ", token).Msg("")

	//-------------------------------Check type of token
	var bearerToken string
	tokenSlice := strings.Split(token, " ")
	if len(tokenSlice) > 1 {
		bearerToken = tokenSlice[len(tokenSlice)-1]
	} else {
		bearerToken = token
	}
	log.Debug().Str("bearerToken : ", bearerToken).Msg("")
	//-----------------------------------------------

	if len(bearerToken) < 1 {
		log.Debug().Msg("Empty Token")
		policyData.Message = "Unauthorized token not informed !!"
		return authService.GeneratePolicyFromClaims(ctx, policyData), nil
	}

	beared_token := core.Credential{ Token: bearerToken }

	// Check which kind of validation JWT
	if appServer.InfoApp.ScopeValidation == true {
		// Check the JWT signed and scope
		claims, response, err = authService.ScopeValidation(ctx, beared_token, path, method)
	} else {
		// Check only the JWT signed (NO SCOPE)
		claims, response, err = authService.TokenValidation(ctx, beared_token)
	}
	log.Debug().Interface("===> claims : ", claims).Msg("")
	policyData.JwtData = claims

	if err != nil {
		switch err {
			case erro.ErrStatusUnauthorized:
				log.Debug().Msg(err.Error())
				policyData.Message = "Failed ScopeValidation - Signature Invalid"
			case erro.ErrTokenExpired:
				log.Debug().Msg(err.Error())
				policyData.Message = "Failed ScopeValidation - Token Expired/Invalid"
			default:
				log.Debug().Msg(err.Error())
				policyData.Message = "Failed ScopeValidation"
		}
		return authService.GeneratePolicyFromClaims(ctx, policyData), nil
	}

	if response == true {
		policyData.Effect = "Allow"
		policyData.Message = "Authorized"
	} else {
		policyData.Message = "Unauthorized by Scope"
	}

	log.Debug().Interface("policyData : ", policyData).Msg("")

	return authService.GeneratePolicyFromClaims(ctx, policyData), nil
}

// Integration APIGW as TOKEN (NO USED)
/*func lambdaHandlerToken(ctx context.Context, request events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
}*/