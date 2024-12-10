package model

import(
	"time"
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v4"
)

type AppServer struct {
	InfoApp 		*InfoApp 		`json:"info_app"`
	ConfigOTEL		*ConfigOTEL		`json:"otel_config"`
}

type InfoApp struct {
	AppName				string `json:"app_name,omitempty"`
	AWSRegion			string `json:"aws_region,omitempty"`
	ApiVersion			string `json:"version,omitempty"`
	TableName			string `json:"table_name,omitempty"`
	ScopeValidation		bool `json:"scope_validation"`
	CrlValidation		bool `json:"crl_validation"`
	CrlBucketNameKey	string `json:"crl_bucket_name_key"`
	CrlFilePath			string `json:"crl_file_path"`
	CrlFileKey			string `json:"crl_file_key"`
	Env					string `json:"env,omitempty"`
	AccountID			string `json:"account,omitempty"`
	BucketNameRSAKey	string `json:"bucket_rsa_key,omitempty"`
	FilePathRSA			string `json:"path_rsa_key,omitempty"`
	FileNameRSAPrivKey	string `json:"file_name_rsa_private_key,omitempty"`
	FileNameRSAPubKey	string `json:"file_name_rsa_public_key,omitempty"`
	SecretJwtKey		string `json:"secret_jwt_key,omitempty"`
	IsTokenRSA			bool `json:"is_token_rsa,y,omitempty"`
}

type ConfigOTEL struct {
	OtelExportEndpoint		string
	TimeInterval            int64    `mapstructure:"TimeInterval"`
	TimeAliveIncrementer    int64    `mapstructure:"RandomTimeAliveIncrementer"`
	TotalHeapSizeUpperBound int64    `mapstructure:"RandomTotalHeapSizeUpperBound"`
	ThreadsActiveUpperBound int64    `mapstructure:"RandomThreadsActiveUpperBound"`
	CpuUsageUpperBound      int64    `mapstructure:"RandomCpuUsageUpperBound"`
	SampleAppPorts          []string `mapstructure:"SampleAppPorts"`
}

type PolicyData struct {
	PrincipalID		string
	Effect			string
	MethodArn		string
	UsageIdentifierKey	*string		
	Message			string		
}

type JwtData struct {
	TokenUse	string 	`json:"token_use"`
	ISS			string 	`json:"iss"`
	Version		string 	`json:"version"`
	JwtId		string 	`json:"jwt_id"`
	Username	string 	`json:"username"`
	Scope	  	[]string `json:"scope"`
	jwt.RegisteredClaims
}

type RSA_Key struct{
	SecretNameH256		string
	JwtKey				string
	Key_rsa_priv_pem	string
	Key_rsa_pub_pem 	string	
	Key_rsa_priv 		*rsa.PrivateKey
	Key_rsa_pub 		*rsa.PublicKey	
}

type UserProfile struct {
	ID				string	`json:"ID,omitempty"`
	SK				string	`json:"SK,omitempty"`
	UsagePlan		string 	`json:"usage_plan,omitempty"`
	ApiKey			string 	`json:"apikey,omitempty"`
	TenantID		string	`json:"tenant_id,omitempty"`
	Updated_at  	time.Time 	`json:"updated_at,omitempty"`
}