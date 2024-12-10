package dynamo

import(
	"context"
	"github.com/rs/zerolog/log"

	"github.com/lambda-go-auth-apigw/pkg/observability"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

var childLogger = log.With().Str("pkg", "database").Logger()

type Database struct {
	Client 		*dynamodb.Client
}

func NewDatabase(ctx context.Context, configAWS *aws.Config) (*Database, error){
	childLogger.Debug().Msg("NewDatabase")

	span := observability.Span(ctx, "repository.NewDatabase")	
    defer span.End()

	client := dynamodb.NewFromConfig(*configAWS)

	return &Database {
		Client: client,
	}, nil
}