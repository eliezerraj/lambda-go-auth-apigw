package repository

import(
	"github.com/rs/zerolog/log"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

var childLogger = log.With().Str("repository", "AuthRepository").Logger()

type AuthRepository struct {
	client 		*dynamodb.Client
	tableName   *string
	awsConfig aws.Config
}

func NewAuthRepository(	tableName string,
						awsConfig aws.Config) (*AuthRepository, error){
	childLogger.Debug().Msg("NewAuthRepository")

	client := dynamodb.NewFromConfig(awsConfig)

	return &AuthRepository {
		client: client,
		tableName: aws.String(tableName),
	}, nil
}
