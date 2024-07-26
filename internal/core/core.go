package core

import (
	"time"

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
	AvailabilityZone 	string `json:"availabilityZone,omitempty"`
	TableName			string `json:"table_name,omitempty"`
	JwtKey				string `json:"jwt_key,omitempty"`
	SSMJwtKey			string `json:"ssm_jwt_key,omitempty"`
	ScopeValidation		bool `json:"scope_vaildation"`
	CrlValidation		bool `json:"crl_validation"`
	CrlBucketNameKey	string `json:"crl_bucket_name_key"`
	CrlFilePath			string `json:"crl_file_path"`
	CrlFileKey			string `json:"crl_file_key"`
	Env					string `json:"env,omitempty"`
	AccountID			string `json:"account,omitempty"`
}

type Credential struct {
	Token	string `json:"token,omitempty"`
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

type UserProfile struct {
	ID				string		`json:"ID,omitempty"`
	SK				string		`json:"SK,omitempty"`
	TenantID		string		`json:"tenant_id,omitempty"`
	Updated_at  	time.Time 	`json:"updated_at,omitempty"`
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
	Effect			string
	MethodArn		string
	JwtData			*JwtData		
	Message			string		
}
