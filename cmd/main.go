package main

import(
	"os"
	"context"
	"strings"
	"errors"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/lambda-go-auth-apigw/internal/service"
	"github.com/lambda-go-auth-apigw/internal/core/domain"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"

)

var (
	logLevel		=	zerolog.DebugLevel // InfoLevel DebugLevel
	version			=	"lambda-go-auth-apigw version 1.0"
	jwtKey			= 	"my_secret_key"
	authService		*service.AuthService
)

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

	authService = service.NewAuthService([]byte(jwtKey))
	lambda.Start(lambdaHandler)
}

func generatePolicy(principalID, effect, resource string) events.APIGatewayCustomAuthorizerResponse {
	log.Debug().Msg("generatePolicy")
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

	// Add variables in context
	authResponse.Context = map[string]interface{}{
		"tenant-id":  "tenant-999",
		"issuer-id":  123,
	}

	log.Debug().Interface("authResponse : ", authResponse).Msg("")
	log.Debug().Interface("authResponse.Context : ", authResponse.Context).Msg("")

	return authResponse
}

func lambdaHandler(ctx context.Context, request events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	log.Debug().Msg("lambdaHandler")
	log.Debug().Interface("request : ", request).Msg("+++++")
	
	arn := strings.SplitN(request.MethodArn, "/", 4)
	method := arn[2]
	path := arn[3]

	log.Debug().Interface("method : ", method).Msg("")
	log.Debug().Interface("path : ", path).Msg("")

	token := request.AuthorizationToken
	tokenSlice := strings.Split(token, " ")
	var bearerToken string

	if len(tokenSlice) > 1 {
		bearerToken = tokenSlice[len(tokenSlice)-1]
	}else{
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized")
	}

	beared_token := domain.Credential{ Token: bearerToken }
	//response, err := authService.TokenValidation(beared_token) // Check just the token 
	response, err := authService.ScopeValidation(beared_token, path, method) //Check token and scope
	if err != nil {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized")
	}
	
	if response == true {
		return generatePolicy("user", "Allow", request.MethodArn), nil
	} else {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized")
	}
}