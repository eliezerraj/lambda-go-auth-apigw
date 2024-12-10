package observability

import(
	"context"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/lambda-go-auth-apigw/internal/model"
    
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/sdk/resource"
)

var authOption otlptracegrpc.Option

func Span(ctx context.Context, spanName string) trace.Span {
	cID, rID := "unknown", "unknown"

	tracer := otel.GetTracerProvider().Tracer("go.opentelemetry.io/otel")
	_, span := tracer.Start(
		ctx,
		spanName,
		trace.WithSpanKind(trace.SpanKindConsumer),
		trace.WithAttributes(
			attribute.String("user_id", cID),
			attribute.String("request_id", rID)),
	)

	return span
}

func Attributes(ctx context.Context, infoApp *model.InfoApp) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("service.name", infoApp.AppName),
		attribute.String("service.version", infoApp.ApiVersion),
		attribute.String("account", infoApp.AccountID),
		attribute.String("service", "lambda"),
		attribute.String("application", infoApp.AppName),
		attribute.String("env", infoApp.Env),
		semconv.TelemetrySDKLanguageGo,
	}
}

func buildResources(ctx context.Context, infoApp *model.InfoApp) (*resource.Resource, error) {
	return resource.New(
		ctx,
		resource.WithAttributes(Attributes(ctx, infoApp)...),
	)
}

func NewTracerProvider(ctx context.Context, configOTEL *model.ConfigOTEL, infoApp *model.InfoApp) *sdktrace.TracerProvider {
	log.Debug().Msg("NewTracerProvider")

	authOption = otlptracegrpc.WithInsecure()

	exporter, err := otlptrace.New(
		ctx,
		otlptracegrpc.NewClient(
			otlptracegrpc.WithRetry(otlptracegrpc.RetryConfig{
				Enabled:         true,
				InitialInterval: time.Millisecond * 100,
				MaxInterval:     time.Millisecond * 500,
				MaxElapsedTime:  time.Second,
			}),
			authOption,
			otlptracegrpc.WithEndpoint(configOTEL.OtelExportEndpoint),
		),
	)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create OTEL trace exporter")
	}

	resources, err := buildResources(ctx, infoApp)
	if err != nil {
		log.Error().Err(err).Msg("Failed to load OTEL resource")
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(sdktrace.NewBatchSpanProcessor(exporter)),
		sdktrace.WithSyncer(exporter),
		sdktrace.WithResource(resources),
	)
	return tp
}