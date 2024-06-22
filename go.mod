module github.com/lambda-go-auth-apigw

go 1.21

toolchain go1.21.3

require (
	github.com/aws/aws-lambda-go v1.47.0
	github.com/aws/aws-sdk-go-v2 v1.27.1
	github.com/aws/aws-sdk-go-v2/config v1.27.17
	github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue v1.14.0
	github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression v1.7.22
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.32.7
	github.com/aws/aws-sdk-go-v2/service/s3 v1.55.0
	github.com/aws/aws-sdk-go-v2/service/ssm v1.50.5
	github.com/aws/aws-xray-sdk-go v1.8.3
	github.com/golang-jwt/jwt/v4 v4.5.0
	github.com/rs/zerolog v1.30.0
	go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-lambda-go/otellambda v0.52.0
	go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-lambda-go/otellambda/xrayconfig v0.52.0
	go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-sdk-go-v2/otelaws v0.52.0
	go.opentelemetry.io/contrib/propagators/aws v1.27.0
	go.opentelemetry.io/otel v1.27.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.27.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.27.0
	go.opentelemetry.io/otel/sdk v1.27.0
	go.opentelemetry.io/otel/trace v1.27.0
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/aws/aws-sdk-go v1.47.9 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.6.2 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.17 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.3.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/dynamodbstreams v1.20.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.11.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.3.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.9.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.11.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.17.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/sqs v1.32.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.20.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.24.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.28.11 // indirect
	github.com/aws/smithy-go v1.20.2 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.20.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/klauspost/compress v1.17.2 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.50.0 // indirect
	go.opentelemetry.io/contrib/detectors/aws/lambda v0.52.0 // indirect
	go.opentelemetry.io/otel/metric v1.27.0 // indirect
	go.opentelemetry.io/proto/otlp v1.2.0 // indirect
	golang.org/x/net v0.25.0 // indirect
	golang.org/x/sys v0.20.0 // indirect
	golang.org/x/text v0.15.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240520151616-dc85e6b867a5 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240520151616-dc85e6b867a5 // indirect
	google.golang.org/grpc v1.64.0 // indirect
	google.golang.org/protobuf v1.34.1 // indirect
)
