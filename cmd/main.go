package main

import(
	"context"
	"strings"
	"errors"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/lambda-go-auth-apigw/internal/service"
	"github.com/lambda-go-auth-apigw/internal/repository"
	"github.com/lambda-go-auth-apigw/internal/lib"

	"github.com/lambda-go-auth-apigw/internal/core"
	"github.com/lambda-go-auth-apigw/internal/util"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/config"

	"go.opentelemetry.io/contrib/propagators/aws/xray"
	"go.opentelemetry.io/otel"
 	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-lambda-go/otellambda"
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-sdk-go-v2/otelaws"
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-lambda-go/otellambda/xrayconfig"
	"go.opentelemetry.io/otel/trace"
)

var (
	logLevel	=	zerolog.DebugLevel // InfoLevel DebugLevel
	authService	*service.AuthService
	appServer	core.AppServer
	response 	bool
	claims 		= &core.JwtData{}
	err 		error
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
	awsConfig, err := config.LoadDefaultConfig(ctx)

	// Instrument all AWS clients.
	otelaws.AppendMiddlewares(&awsConfig.APIOptions)

	// Get Parameter-Store
	if err != nil {
		panic("configuration error create new aws session " + err.Error())
	}
		
	ssmsvc := ssm.NewFromConfig(awsConfig)
	param, err := ssmsvc.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(appServer.InfoApp.SSMJwtKey),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		panic("configuration error get parameter " + err.Error())
	}
	jwtKey := *param.Parameter.Value

	log.Debug().Str("======== > ssmJwtKwy", appServer.InfoApp.SSMJwtKey).Msg("")
	log.Debug().Str("======== > jwtKey", jwtKey).Msg("")

	// Create a repository
	authRepository, err := repository.NewAuthRepository(appServer.InfoApp.TableName, awsConfig)
	if err != nil {
		panic("configuration error AuthRepository(), " + err.Error())
	}

	// Load the CRL
	if appServer.InfoApp.CrlValidation == true {
		load_crl_pem, err = util.LoadKeyAsFileS3(ctx, 
												awsConfig, 
												appServer.InfoApp.CrlBucketNameKey,
												appServer.InfoApp.CrlFilePath,
												appServer.InfoApp.CrlFileKey)
		if err != nil {
			log.Error().Err(err).Msg("Erro LoadKeyAsFileS3")
		}
	}

	// Create a service
	authService = service.NewAuthService([]byte(jwtKey), authRepository)
		
	//----- OTEL ----//
	tp := lib.NewTracerProvider(ctx, appServer.ConfigOTEL, appServer.InfoApp)
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
	// Start lambda handler
	//lambda.Start(lambdaHandlerRequest)
}

func generatePolicy(ctx context.Context, 
					principalID string, 
					effect string, 
					resource string) events.APIGatewayCustomAuthorizerResponse {
	log.Debug().Msg("generatePolicy")
	
	span := lib.Span(ctx, "generatePolicy")	
    defer span.End()

	// Create a policy
	authResponse := events.APIGatewayCustomAuthorizerResponse{PrincipalID: principalID}
	if effect != "" && resource != "" {
		authResponse.PolicyDocument = events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   effect,
					Resource: []string{resource},
				},
			},
		}
	}

	// Query the user-profile to inject tenant-id in the header
	userProfile := core.UserProfile{ID: principalID}
	res_userProfile, _ := authService.LoadUserProfile(ctx, userProfile)
	// Add variables in context
	if res_userProfile != nil {
		authResponse.Context = map[string]interface{}{
			"tenant-id":  res_userProfile.TenantID,
		}
	}

	return authResponse
}

func generatePolicyError(ctx context.Context, 
						resource string, 
						message string) events.APIGatewayCustomAuthorizerResponse {
	log.Debug().Msg("generatePolicyError")
	
	span := lib.Span(ctx, "geratePolicyError")	
    defer span.End()

	authResponse := events.APIGatewayCustomAuthorizerResponse{PrincipalID: ""}
	authResponse.PolicyDocument = events.APIGatewayCustomAuthorizerPolicy{
		Version: "2012-10-17",
		Statement: []events.IAMPolicyStatement{
			{
				Action:   []string{"execute-api:Invoke"},
				Effect:   "Deny",
				Resource: []string{resource},
			},
		},
	}

	authResponse.Context = make(map[string]interface{})
	authResponse.Context["customErrorMessage"] = message

	log.Debug().Msg("--------------------------------------------------------")
	log.Debug().Interface("generatePolicyError:", authResponse).Msg("")
	log.Debug().Msg("--------------------------------------------------------")

	return authResponse
}

// Integration APIGW as Request (USED)
// When use lambda authorizer type Request
func lambdaHandlerRequest(ctx context.Context, request events.APIGatewayCustomAuthorizerRequestTypeRequest ) (events.APIGatewayCustomAuthorizerResponse, error) {
	log.Debug().Msg("lambdaHandlerRequest")
	log.Debug().Msg("-------------------")
	log.Debug().Interface("request : ", request).Msg("")

	ctx, span := tracer.Start(ctx, "lambdaHandlerRequest")
    defer span.End()

	// Check CRL
	if appServer.InfoApp.CrlValidation == true {
		CertX509PemDecoded := request.RequestContext.Identity.ClientCert.ClientCertPem
		log.Debug().Interface("Client CertX509PemDecoded : ", CertX509PemDecoded).Msg("")
		
		// The cert must be informed
		if CertX509PemDecoded == ""{
			log.Info().Msg("Client Cert no Informed !!!")
			return generatePolicyError(ctx, request.MethodArn ,"Unauthorized Certificate not Informed !!!!"), nil
		}
		
		certX509, err := util.ParsePemToCertx509(CertX509PemDecoded)
		if err != nil {
			log.Debug().Msg("Erro ParsePemToCertx509!!!")
		}
		response_crl, err := authService.VerifyCertCRL(ctx, *load_crl_pem, certX509)
		if err != nil {
			log.Debug().Msg("Unauthorized Cert Revoked !!!")
			//return generatePolicyError(ctx, request.MethodArn ,"Unauthorized ScopeValidation NOT allowed"), nil
		}
		log.Debug().Interface(" ====> CrlValidation response : ", response_crl).Msg("")
		// response_crl is true means the cert is revoked
		if response_crl == true {
			return generatePolicyError(ctx, request.MethodArn ,"Unauthorized Certificate revoked"), nil
		}
	}

	// Check the size of arn
	if (len(request.MethodArn) < 6){
		log.Debug().Str("request.MethodArn size error : ", string(len(request.MethodArn))).Msg("")
		return generatePolicyError(ctx, request.MethodArn ,"Unauthorized arr mal-formed"), nil
	}

	// Parse the method and path
	arn := strings.SplitN(request.MethodArn, "/", 4)
	method := arn[2]
	path := arn[3]

	log.Debug().Interface("method : ", method).Msg("")
	log.Debug().Interface("path : ", path).Msg("")

	var token string
	// Extract the token from header
	if (request.Headers["Authorization"] != "")  {
		token = request.Headers["Authorization"]
	} else if (request.Headers["authorization"] != "") {
		token = request.Headers["authorization"]
	}

	log.Debug().Str("token : ", token).Msg("")

	//Check type of token
	var bearerToken string
	tokenSlice := strings.Split(token, " ")
	if len(tokenSlice) > 1 {
		bearerToken = tokenSlice[len(tokenSlice)-1]
	} else {
		bearerToken = token
	}

	log.Debug().Str("bearerToken : ", bearerToken).Msg("")

	if len(bearerToken) < 1 {
		log.Debug().Msg("Empty Token")
		return generatePolicyError(ctx, request.MethodArn ,"Unauthorized token not informed !!!"), nil
	}

	beared_token := core.Credential{ Token: bearerToken }

	// Check which kind of validation JWT
	if appServer.InfoApp.ScopeValidation == true {
		// Check the JWT signed and scope
		claims, response, err = authService.ScopeValidation(ctx, beared_token, path, method)
	} else {
		// Check only the JWT signed (NO SCOPE)
		response, err = authService.TokenValidation(ctx, beared_token)
	}

	if err != nil {
		log.Debug().Msg("Failed ScopeValidation")
		return generatePolicyError(ctx, request.MethodArn , err.Error()), nil
	}
	if response == false {
		log.Debug().Msg("Unauthorized ScopeValidation")
		return generatePolicyError(ctx, request.MethodArn ,"Unauthorized ScopeValidation NOT allowed"), nil
	}

	if response == true {
		return generatePolicy(ctx, claims.Username, "Allow", request.MethodArn), nil
	} else {
		return generatePolicyError(ctx, request.MethodArn ,"Unauthorized"), nil
	}
}

// Integration APIGW as TOKEN (NO USED)
// When use lambda authorizer type Token
func lambdaHandlerToken(ctx context.Context, request events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	log.Debug().Msg("lambdaHandlerToken")
	log.Debug().Msg("-------------------")
	log.Debug().Interface("request : ", request).Msg("")


	// Check the size of arn
	if (len(request.MethodArn) < 6){
		log.Debug().Str("request.MethodArn size error : ", string(len(request.MethodArn))).Msg("")
		return generatePolicyError(ctx, request.MethodArn ,"Unauthorized"), nil
	}
	
	arn := strings.SplitN(request.MethodArn, "/", 4)
	method := arn[2]
	path := arn[3]

	log.Debug().Interface("method : ", method).Msg("")
	log.Debug().Interface("path : ", path).Msg("")

	// Extract the token from header
	token := request.AuthorizationToken
	tokenSlice := strings.Split(token, " ")
	var bearerToken string

	if len(tokenSlice) > 1 {
		bearerToken = tokenSlice[len(tokenSlice)-1]
	}else{
		log.Debug().Msg("Empty Token")
		return generatePolicyError(ctx, request.MethodArn ,"Unauthorized Token not informed !!!!"), nil
	}

	beared_token := core.Credential{ Token: bearerToken }

	if appServer.InfoApp.ScopeValidation == true {
		// Check the JWT signed and scope
		claims, response, err = authService.ScopeValidation(ctx, beared_token, path, method)
	} else {
		// Check only the JWT signed (NO SCOPE)
		response, err = authService.TokenValidation(ctx, beared_token)
	}

	if err != nil {
		log.Debug().Msg("Failed ScopeValidation")
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized error ScopeValidation")
	}
	if response == false {
		log.Debug().Msg("Unauthorized ScopeValidation")
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized ScopeValidation not allowed")
	}

	if response == true {
		return generatePolicy(ctx, claims.Username, "Allow", request.MethodArn), nil
	} else {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized !!!!")
	}
}
