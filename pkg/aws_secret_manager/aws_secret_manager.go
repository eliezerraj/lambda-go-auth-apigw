package aws_secret_manager

import (
	"context"
	
	"github.com/rs/zerolog/log"
	"github.com/lambda-go-auth-apigw/pkg/observability"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

var childLogger = log.With().Str("pkg", "aws_secret_manager").Logger()

type AwsClientSecretManager struct {
	Client *secretsmanager.Client
}

func NewClientSecretManager(configAWS *aws.Config) (*AwsClientSecretManager, error) {
	childLogger.Debug().Msg("NewClientSecretManager")
		
	client := secretsmanager.NewFromConfig(*configAWS)
	return &AwsClientSecretManager{
		Client: client,
	}, nil
}

func (p *AwsClientSecretManager) GetSecret(ctx context.Context, secretName string) (*string, error) {

	span := observability.Span(ctx, "aws_secret_manager.GetSecret")	
    defer span.End()

	result, err := p.Client.GetSecretValue(ctx, 
										&secretsmanager.GetSecretValueInput{
											SecretId:		aws.String(secretName),
											VersionStage:	aws.String("AWSCURRENT"),
										})
	if err != nil {
		return nil, err
	}
	return result.SecretString, nil
}