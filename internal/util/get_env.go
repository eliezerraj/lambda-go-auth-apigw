package util

import(
	"os"
	"github.com/rs/zerolog/log"
	"github.com/lambda-go-auth-apigw/internal/core"
)

func GetAppInfo() core.AppServer {
	log.Debug().Msg("getEnv")

	var appServer	core.AppServer
	var infoApp		core.InfoApp

	if os.Getenv("APP_NAME") !=  "" {
		infoApp.AppName = os.Getenv("APP_NAME")
	}

	if os.Getenv("REGION") !=  "" {
		infoApp.AWSRegion = os.Getenv("REGION")
	}

	if os.Getenv("VERSION") !=  "" {
		infoApp.ApiVersion = os.Getenv("VERSION")
	}

	if os.Getenv("JWT_KEY") !=  "" {
		infoApp.JwtKey = os.Getenv("JWT_KEY")
	}

	if os.Getenv("SSM_JWT_KEY") !=  "" {
		infoApp.SSMJwtKey = os.Getenv("SSM_JWT_KEY")
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

	appServer.InfoApp = &infoApp

	return appServer
}