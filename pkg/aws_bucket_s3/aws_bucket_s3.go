package aws_bucket_s3

import (
	"context"
	"io"
	"github.com/rs/zerolog/log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

var childLogger = log.With().Str("pkg", "bucket_s3").Logger()

type AwsClientBucketS3 struct {
	Client *s3.Client
}

func NewClientS3Bucket(awsConfig aws.Config) *AwsClientBucketS3 {
	childLogger.Debug().Msg("NewClientS3Bucket")

	client := s3.NewFromConfig(awsConfig)
	
	return &AwsClientBucketS3{
		Client: client,
	}
}

func (p *AwsClientBucketS3) GetObject(	ctx context.Context, 	
										bucketNameKey 	string,
										filePath 		string,
										fileKey 		string) (*[]byte, error) {
	childLogger.Debug().Msg("GetObject")

	getObjectInput := &s3.GetObjectInput{
						Bucket: aws.String(bucketNameKey+filePath),
						Key:    aws.String(fileKey),
	}

	getObjectOutput, err := p.Client.GetObject(ctx, getObjectInput)
	if err != nil {
		return nil, err
	}
	defer getObjectOutput.Body.Close()

	bodyBytes, err := io.ReadAll(getObjectOutput.Body)
	if err != nil {
		return nil, err
	}

	return &bodyBytes, nil
}