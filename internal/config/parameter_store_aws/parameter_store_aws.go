package parameter_store_aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

type AwsClientParameterStore struct {
	Client *ssm.Client
}

func NewClientParameterStore(awsConfig aws.Config) *AwsClientParameterStore {
	client := ssm.NewFromConfig(awsConfig)
	return &AwsClientParameterStore{
		Client: client,
	}
}

func (p *AwsClientParameterStore) GetParameter(ctx context.Context, parameterName string) (*string, error) {
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