package repository

import(
	"os"

	"github.com/rs/zerolog/log"
	"github.com/lambda-go-auth-apigw/internal/erro"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
)

var childLogger = log.With().Str("repository", "AuthRepository").Logger()

type AuthRepository struct {
	client 		dynamodbiface.DynamoDBAPI
	tableName   *string
}

func NewAuthRepository(tableName string) (*AuthRepository, error){
	childLogger.Debug().Msg("NewAuthRepository")

	region := os.Getenv("AWS_REGION")
    awsSession, err := session.NewSession(&aws.Config{
        Region: aws.String(region)},
    )
	if err != nil {
		childLogger.Error().Err(err).Msg("error message")
		return nil, erro.ErrOpenDatabase
	}

	return &AuthRepository {
		client: dynamodb.New(awsSession),
		tableName: aws.String(tableName),
	}, nil
}
