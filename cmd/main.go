package main

import(
	"os"
	"context"
	"strings"
	"errors"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/lambda-go-auth-apigw/internal/service"
	"github.com/lambda-go-auth-apigw/internal/repository"
	"github.com/lambda-go-auth-apigw/internal/core/domain"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"

	"github.com/aws/aws-xray-sdk-go/xray"
)

var (
	logLevel		=	zerolog.DebugLevel // InfoLevel DebugLevel
	version			=	"lambda-go-auth-apigw version 1.0"
	jwtKey			=	"my_secret_key"
	ssmJwtKwy		=	"key-secret"
	tableName		=	"user-profile"
	authService		*service.AuthService
	region			=	"us-east-2"
)

// Loading ENV variables
func getEnv(){
	if os.Getenv("LOG_LEVEL") !=  "" {
		if (os.Getenv("LOG_LEVEL") == "DEBUG"){
			logLevel = zerolog.DebugLevel
		}else if (os.Getenv("LOG_LEVEL") == "INFO"){
			logLevel = zerolog.InfoLevel
		}else if (os.Getenv("LOG_LEVEL") == "ERROR"){
				logLevel = zerolog.ErrorLevel
		}else {
			logLevel = zerolog.DebugLevel
		}
	}
	if os.Getenv("VERSION") !=  "" {
		version = os.Getenv("VERSION")
	}

	if os.Getenv("JWT_KEY") !=  "" {
		jwtKey = os.Getenv("JWT_KEY")
	}

	if os.Getenv("AWS_REGION") !=  "" {
		region = os.Getenv("AWS_REGION")
	}
}

func init() {
	log.Debug().Msg("init")
	zerolog.SetGlobalLevel(logLevel)
	getEnv()
}

func main() {
	log.Debug().Msg("main")

	// Get Parameter-Store
	awsConfig := &aws.Config{Region: aws.String(region)}
	awsSession, err := session.NewSession(awsConfig)
	if err != nil {
		panic("configuration error create new aws session " + err.Error())
	}
	
	ssmsvc := ssm.New(awsSession, awsConfig)
	param, err := ssmsvc.GetParameter(&ssm.GetParameterInput{
		Name:           aws.String(ssmJwtKwy),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		panic("configuration error get parameter " + err.Error())
	}
	jwtKey = *param.Parameter.Value

	log.Debug().Str("======== > ssmJwtKwy", ssmJwtKwy).Msg("")
	log.Debug().Str("======== > jwtKey", jwtKey).Msg("")

	// Create a repository
	authRepository, err := repository.NewAuthRepository(tableName)
	if err != nil {
		panic("configuration error AuthRepository(), " + err.Error())
	}

	// Create a service
	authService = service.NewAuthService([]byte(jwtKey), authRepository)
	
	// Start lambda handler
	lambda.Start(lambdaHandlerRequest)
}

func generatePolicy(ctx context.Context, principalID string, effect string, resource string) events.APIGatewayCustomAuthorizerResponse {
	log.Debug().Msg("generatePolicy")

	_, root := xray.BeginSubsegment(ctx, "Handler.generatePolicy")
	defer root.Close(nil)

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
	userProfile := domain.UserProfile{ID: principalID}
	res_userProfile, _ := authService.LoadUserProfile(ctx, userProfile)
	// Add variables in context
	if res_userProfile != nil {
		authResponse.Context = map[string]interface{}{
			"tenant-id":  res_userProfile.TenantID,
		}
	}

	return authResponse
}

func generatePolicyError(ctx context.Context, resource string, message string) events.APIGatewayCustomAuthorizerResponse {
	log.Debug().Msg("generatePolicyError")

	_, root := xray.BeginSubsegment(ctx, "Handler.generatePolicyError")
	defer root.Close(nil)

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

// When use lambda authorizer type Request
func lambdaHandlerRequest(ctx context.Context, request events.APIGatewayCustomAuthorizerRequestTypeRequest ) (events.APIGatewayCustomAuthorizerResponse, error) {
	log.Debug().Msg("lambdaHandler")
	log.Debug().Msg("-------------------")
	log.Debug().Interface("request : ", request).Msg("")
	log.Debug().Msg("--------------------")

	_, root := xray.BeginSubsegment(ctx, "Handler.Lambda")
	defer root.Close(nil)

	// Parse the method and path
	arn := strings.SplitN(request.MethodArn, "/", 4)
	method := arn[2]
	path := arn[3]

	log.Debug().Interface("method : ", method).Msg("")
	log.Debug().Interface("path : ", path).Msg("")

	// Extract the token from header
	token := request.Headers["Authorization"]

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
		return generatePolicyError(ctx, request.MethodArn ,"Unauthorized Token Null"), nil
	}

	beared_token := domain.Credential{ Token: bearerToken }

	// Check only the JWT signed
	//response, err := authService.TokenValidation(beared_token) // Check just the token 
	
	// Check the JWT signed and scope
	claims, response, err := authService.ScopeValidation(ctx, beared_token, path, method) //Check token and scope
	if err != nil {
		log.Error().Msg("authService.ScopeValidation")

		return generatePolicyError(ctx, request.MethodArn ,"Unauthorized ScopeValidation failed"), nil
	}
	if response == false {
		return generatePolicyError(ctx, request.MethodArn ,"Unauthorized ScopeValidation not allowed"), nil
	}

	if response == true {
		return generatePolicy(ctx, claims.Username, "Allow", request.MethodArn), nil
	} else {
		return generatePolicyError(ctx, request.MethodArn ,"Unauthorized"), nil
	}
}

// When use lambda authorizer type Token
func lambdaHandlerToken(ctx context.Context, request events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	log.Debug().Msg("lambdaHandler")
	log.Debug().Msg("-------------------")
	log.Debug().Interface("request : ", request).Msg("")
	log.Debug().Msg("--------------------")

	_, root := xray.BeginSubsegment(ctx, "Handler.Lambda")
	defer root.Close(nil)

	// Parse the method and path
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
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized - Token Null")
	}

	beared_token := domain.Credential{ Token: bearerToken }

	// Check only the JWT signed
	//response, err := authService.TokenValidation(beared_token) // Check just the token 
	
	// Check the JWT signed and scope
	claims, response, err := authService.ScopeValidation(ctx, beared_token, path, method) //Check token and scope
	if err != nil {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized error ScopeValidation")
	}
	if response == false {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized ScopeValidation not allowed")
	}

	if response == true {
		return generatePolicy(ctx, claims.Username, "Allow", request.MethodArn), nil
	} else {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized !!!!")
	}
}
