package util

import(
	"os"

	"github.com/rs/zerolog/log"
	"github.com/lambda-go-auth-apigw/internal/model"
)

func GetAppInfo() model.InfoApp {
	log.Debug().Msg("GetAppInfo")

	var infoApp		model.InfoApp

	if os.Getenv("APP_NAME") !=  "" {
		infoApp.AppName = os.Getenv("APP_NAME")
	}

	if os.Getenv("REGION") !=  "" {
		infoApp.AWSRegion = os.Getenv("REGION")
	}

	if os.Getenv("VERSION") !=  "" {
		infoApp.ApiVersion = os.Getenv("VERSION")
	}

	if os.Getenv("TABLE_NAME") !=  "" {
		infoApp.TableName = os.Getenv("TABLE_NAME")
	}

	if os.Getenv("SCOPE_VALIDATION") ==  "true" {
		infoApp.ScopeValidation = true
	}else{
		infoApp.ScopeValidation = false
	}

	if os.Getenv("CRL_VALIDATION") ==  "true" {
		infoApp.CrlValidation = true
	}else{
		infoApp.CrlValidation = false
	}

	if os.Getenv("CRL_BUCKET_NAME_KEY") !=  "" {
		infoApp.CrlBucketNameKey = os.Getenv("CRL_BUCKET_NAME_KEY")
	}

	if os.Getenv("CRL_FILE_PATH") !=  "" {
		infoApp.CrlFilePath = os.Getenv("CRL_FILE_PATH")
	}

	if os.Getenv("CRL_FILE_KEY") !=  "" {
		infoApp.CrlFileKey = os.Getenv("CRL_FILE_KEY")
	}

	if os.Getenv("SECRET_JWT_KEY") !=  "" {
		infoApp.SecretJwtKey = os.Getenv("SECRET_JWT_KEY")
	}

	if os.Getenv("RSA_BUCKET_NAME_KEY") !=  "" {
		infoApp.BucketNameRSAKey = os.Getenv("RSA_BUCKET_NAME_KEY")
	}

	if os.Getenv("RSA_FILE_PATH") !=  "" {
		infoApp.FilePathRSA = os.Getenv("RSA_FILE_PATH")
	}

	if os.Getenv("RSA_PRIV_FILE_KEY") !=  "" {
		infoApp.FileNameRSAPrivKey = os.Getenv("RSA_PRIV_FILE_KEY")
	}

	if os.Getenv("RSA_PUB_FILE_KEY") !=  "" {
		infoApp.FileNameRSAPubKey = os.Getenv("RSA_PUB_FILE_KEY")
	}

	if os.Getenv("IS_TOKEN_RSA") ==  "true" {
		infoApp.IsTokenRSA = true
	}else{
		infoApp.IsTokenRSA = false
	}

	return infoApp
}