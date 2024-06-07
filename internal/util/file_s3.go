package util

import(
	"bytes"
	"context"
	"io"
	"crypto/sha256"
	"encoding/hex"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func SaveKeyAsFileS3(ctx context.Context,
					awsConfig aws.Config,
					bucketNameKey 	string,
					filePath 		string,
					fileKey 		string,
					fileData		[]byte) error {
	childLogger.Debug().Msg("SaveKeyAsFileS3")
	childLogger.Debug().Msg("bucketNameKey :" + bucketNameKey + filePath + fileKey)

	s3Client := s3.NewFromConfig(awsConfig)

	// Calc sha256sum
    hash := sha256.New()
    _, err:= io.Copy(hash, bytes.NewReader(fileData))    
    if err != nil {
		childLogger.Error().Err(err).Msg("Hash error")
        return err
    }
	var s3_tag = "sha256sum=" + hex.EncodeToString(hash.Sum(nil))

	putObjectInput := &s3.PutObjectInput{
		Bucket: aws.String(bucketNameKey),
		Key:    aws.String(fileKey),
		Body:   bytes.NewReader(fileData),
		Tagging: aws.String(s3_tag),
	}

	putObjectResult, err := s3Client.PutObject(ctx, putObjectInput)
	if err != nil {
		childLogger.Error().Err(err).Msg("Error uploading file to S3")
		return err
	}

	childLogger.Debug().Msg("ETag :" + *putObjectResult.ETag)
	//fmt.Println("ETag:", *putObjectResult.ETag)
    return nil
}

func LoadKeyAsFileS3(ctx context.Context,
					awsConfig aws.Config,
					bucketNameKey 	string,
					filePath 		string,
					fileKey 		string) (*[]byte, error) {
	childLogger.Debug().Msg("LoadKeyAsFileS3")
	childLogger.Debug().Msg("bucketNameKey :" + bucketNameKey + filePath + fileKey)

	s3Client := s3.NewFromConfig(awsConfig)

	getObjectInput := &s3.GetObjectInput{
						Bucket: aws.String(bucketNameKey+filePath),
						Key:    aws.String(fileKey),
	}

	getObjectOutput, err := s3Client.GetObject(ctx, getObjectInput)
	if err != nil {
		childLogger.Error().Err(err).Msg("Error get object from S3")
		return nil, err
	}
	defer getObjectOutput.Body.Close()

	bodyBytes, err := io.ReadAll(getObjectOutput.Body)
	if err != nil {
		childLogger.Error().Err(err).Msg("Error convert object from S3")
		return nil, err
	}

	return &bodyBytes, nil
}