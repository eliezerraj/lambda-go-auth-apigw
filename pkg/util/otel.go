package util

import(
	"os"
	"github.com/rs/zerolog/log"

	"github.com/lambda-go-auth-apigw/internal/model"
)

func GetOtelEnv() model.ConfigOTEL {
	log.Debug().Msg("GetOtelEnv")

	var configOTEL	model.ConfigOTEL

	configOTEL.TimeInterval = 1
	configOTEL.TimeAliveIncrementer = 1
	configOTEL.TotalHeapSizeUpperBound = 100
	configOTEL.ThreadsActiveUpperBound = 10
	configOTEL.CpuUsageUpperBound = 100
	configOTEL.SampleAppPorts = []string{}

	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") !=  "" {	
		configOTEL.OtelExportEndpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	}

	return configOTEL
}