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

)

var (
	logLevel		=	zerolog.DebugLevel // InfoLevel DebugLevel
	version			=	"lambda-go-auth-apigw version 1.0"
	jwtKey			=	"my_secret_key"
	tableName		=	"user-profile"
	authService		*service.AuthService
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
}

func init() {
	log.Debug().Msg("init")
	zerolog.SetGlobalLevel(logLevel)
	getEnv()
}

func main() {
	log.Debug().Msg("main")

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