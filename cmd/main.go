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

	log.Debug().Interface("jwtKey : ", jwtKey).Msg("")

	// Create a repository
	authRepository, err := repository.NewAuthRepository(tableName)
	if err != nil {
		panic("configuration error AuthRepository(), " + err.Error())
	}

	// Create a service
	authService = service.NewAuthService([]byte(jwtKey), authRepository)
	
	// Start lambda handler
	lambda.Start(lambdaHandler)
}

func generatePolicy(principalID, effect, resource string) events.APIGatewayCustomAuthorizerResponse {
	log.Debug().Msg("generatePolicy")

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
	res_userProfile, _ := authService.LoadUserProfile(userProfile)
	// Add variables in context
	if res_userProfile != nil {
		authResponse.Context = map[string]interface{}{
			"tenant-id":  res_userProfile.TenantID,
		}
	}

	return authResponse
}

func lambdaHandler(ctx context.Context, request events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	log.Debug().Msg("lambdaHandler")
	log.Debug().Interface("request : ", request).Msg("+++++")
	
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
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized")
	}

	beared_token := domain.Credential{ Token: bearerToken }

	// Check only the JWT signed
	//response, err := authService.TokenValidation(beared_token) // Check just the token 
	
	// Check the JWT and scope
	response, err := authService.ScopeValidation(beared_token, path, method) //Check token and scope
	if err != nil {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized")
	}
	
	//Extract user for JWT
	claims, err := authService.ExtractClaims(beared_token)
	if err != nil {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized")
	}

	if response == true {
		return generatePolicy(claims.Username, "Allow", request.MethodArn), nil
	} else {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized")
	}
}