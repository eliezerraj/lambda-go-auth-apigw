package aws_parameter

import (
	"context"

	"github.com/rs/zerolog/log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

var childLogger = log.With().Str("pkg", "parameter").Logger()

type AwsClientParameterStore struct {
	Client *ssm.Client
}

func NewClientParameterStore(awsConfig aws.Config) *AwsClientParameterStore {
	childLogger.Debug().Msg("NewClientParameterStore")

	client := ssm.NewFromConfig(awsConfig)
	return &AwsClientParameterStore{
		Client: client,
	}
}

func (p *AwsClientParameterStore) GetParameter(ctx context.Context, parameterName string) (*string, error) {
	childLogger.Debug().Msg("GetParameter")

	result, err := p.Client.GetParameter(ctx, 
										&ssm.GetParameterInput{
											Name:	aws.String(parameterName),
											WithDecryption:	aws.Bool(false),
										})
	if err != nil {
		return nil, err
	}
	return result.Parameter.Value, nil
}