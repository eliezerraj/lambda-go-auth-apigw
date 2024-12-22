package main

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/lambda-go-auth-apigw/internal/usecase/certs"
	"github.com/lambda-go-auth-apigw/internal/usecase/policy"
	"github.com/lambda-go-auth-apigw/internal/usecase/jwt"
	"github.com/lambda-go-auth-apigw/internal/usecase/jwt/repository"
	"github.com/lambda-go-auth-apigw/internal/model"
	"github.com/lambda-go-auth-apigw/configs"
	
	database "github.com/lambda-go-auth-apigw/pkg/database/dynamo"

	"github.com/lambda-go-auth-apigw/pkg/util"
	"github.com/lambda-go-auth-apigw/pkg/aws_bucket_s3"
	"github.com/lambda-go-auth-apigw/pkg/aws_secret_manager"

	"github.com/lambda-go-auth-apigw/pkg/handler/apigw"
	"github.com/lambda-go-auth-apigw/pkg/observability"

	"github.com/aws/aws-lambda-go/lambda"

	"go.opentelemetry.io/contrib/propagators/aws/xray"
	"go.opentelemetry.io/otel"
 	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-lambda-go/otellambda"
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-lambda-go/otellambda/xrayconfig"
	"go.opentelemetry.io/otel/trace"
)

var (
	logLevel = zerolog.DebugLevel // InfoLevel DebugLevel
	appServer	model.AppServer
	tracer 		trace.Tracer
	rsaKey		model.RSA_Key
)

func init(){
	log.Info().Msg("init")

	zerolog.SetGlobalLevel(logLevel)

	infoApp := util.GetAppInfo()
	configOTEL := util.GetOtelEnv()

	appServer.InfoApp = &infoApp
	appServer.ConfigOTEL = &configOTEL

	log.Info().Interface("appServer : ", appServer).Msg(".")
}

func main(){
	log.Info().Msg("main")
	
	ctx := context.Background()
	configAWS, err := configs.GetAWSConfig(ctx, appServer.InfoApp.AWSRegion)
	if err != nil {
		panic("configuration error create new aws session " + err.Error())
	}

	//Load CRL
	clientS3 := aws_bucket_s3.NewClientS3Bucket(*configAWS)
	crl_pem, err := clientS3.GetObject(	ctx, 
										appServer.InfoApp.CrlBucketNameKey,
										appServer.InfoApp.CrlFilePath,
										appServer.InfoApp.CrlFileKey)
	if err != nil {
		log.Error().Err(err).Msg("Erro NewClientS3Bucket")
	}
	key_rsa_priv_pem, err := clientS3.GetObject(	ctx, 
										appServer.InfoApp.BucketNameRSAKey,
										appServer.InfoApp.FilePathRSA,
										appServer.InfoApp.FileNameRSAPrivKey)
	if err != nil {
		log.Error().Err(err).Msg("Erro GetObject")
	}
	key_rsa_pub_pem, err := clientS3.GetObject(	ctx, 
										appServer.InfoApp.BucketNameRSAKey,
										appServer.InfoApp.FilePathRSA,
										appServer.InfoApp.FileNameRSAPubKey)
	if err != nil {
		log.Error().Err(err).Msg("Erro GetObject")
	}

	//Load symetric key from secret manager
	clientSecretManager, err := aws_secret_manager.NewClientSecretManager(configAWS)
	jwtKey, err := clientSecretManager.GetSecret(ctx, appServer.InfoApp.SecretJwtKey)
	if err != nil {
		log.Error().Err(err).Msg("erro NewClientSecretManager")
	}

	// Create client database repository
	database, err := database.NewDatabase(ctx, configAWS)
	if err != nil {
		panic("Erro repository.NewAuthRepository, " + err.Error())
	}

	repoJwt:= repository.NewRepoJwt(database, &appServer.InfoApp.TableName)

	rsaKey.JwtKey = *jwtKey
	rsaKey.Key_rsa_priv_pem = string(*key_rsa_priv_pem)
	rsaKey.Key_rsa_pub_pem = string(*key_rsa_pub_pem)
	rsaKey.Crl_pem = string(*crl_pem)

	usecaseCerts 	:= certs.NewUseCaseCerts(&rsaKey.Crl_pem)
	usecasePolicy 	:= policy.NewUseCaseCPolicy()
	useCaseJwt, err := jwt.NewUseCaseJwt(ctx, repoJwt, &rsaKey)
	if err != nil {
		log.Error().Err(err).Msg("erro NewUseCaseJwt")
		panic(err)
	}

	tp := observability.NewTracerProvider(ctx, appServer.ConfigOTEL, appServer.InfoApp)
	defer func(ctx context.Context) {
			err := tp.Shutdown(ctx)
			if err != nil {
				log.Error().Err(err).Msg("Error shutting down tracer provider")
			}
	}(ctx)
	
	otel.SetTextMapPropagator(xray.Propagator{})
	otel.SetTracerProvider(tp)
	tracer = tp.Tracer("lambda-go-auth-apigw")

	handler := apigw.InitializeLambdaHandler(	*usecaseCerts, 
												*usecasePolicy, 
												*useCaseJwt, 
												appServer.InfoApp.IsTokenRSA,
												appServer.InfoApp.CrlValidation,
												appServer.InfoApp.ScopeValidation)
	lambda.Start(otellambda.InstrumentHandler(handler.LambdaHandlerRequest, xrayconfig.WithRecommendedOptions(tp)... ))
	//lambda.Start(handler.LambdaHandlerRequest)
}