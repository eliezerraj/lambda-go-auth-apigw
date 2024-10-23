package repository

import(
	"context"

	"github.com/lambda-go-auth-apigw/internal/config/observability"
	"github.com/lambda-go-auth-apigw/internal/config/config_aws"
	"github.com/rs/zerolog/log"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

var childLogger = log.With().Str("repository", "AuthRepository").Logger()

type AuthRepository struct {
	client 		*dynamodb.Client
	tableName   *string
}

func NewAuthRepository(ctx context.Context,	
						tableName string) (*AuthRepository, error){
	childLogger.Debug().Msg("NewAuthRepository")

	span := observability.Span(ctx, "repository.NewAuthRepository")	
    defer span.End()

	sdkConfig, err := config_aws.GetAWSConfig(ctx)
	if err != nil{
		return nil, err
	}

	client := dynamodb.NewFromConfig(*sdkConfig)

	return &AuthRepository {
		client: client,
		tableName: aws.String(tableName),
	}, nil
}
