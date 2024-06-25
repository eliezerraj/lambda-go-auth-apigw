package bucket_s3_aws

import (
	"context"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type AwsClientBucketS3 struct {
	Client *s3.Client
}

func NewClientS3Bucket(awsConfig aws.Config) *AwsClientBucketS3 {
	client := s3.NewFromConfig(awsConfig)
	return &AwsClientBucketS3{
		Client: client,
	}
}

func (p *AwsClientBucketS3) GetObject(	ctx context.Context, 	
										bucketNameKey 	string,
										filePath 		string,
										fileKey 		string) (*[]byte, error) {

	getObjectInput := &s3.GetObjectInput{
						Bucket: aws.String(bucketNameKey+filePath),
						Key:    aws.String(fileKey),
	}

	getObjectOutput, err := p.Client.GetObject(ctx, getObjectInput)
	defer getObjectOutput.Body.Close()
	if err != nil {
		return nil, err
	}
	
	bodyBytes, err := io.ReadAll(getObjectOutput.Body)
	if err != nil {
		return nil, err
	}

	return &bodyBytes, nil
}