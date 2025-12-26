package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	zmq "github.com/go-zeromq/zmq4" // just want some of the enums, nothing else 😜
	"github.com/google/uuid"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	mymetrics "github.com/lqqyt2423/go-mitmproxy/metrics"
	mytracing "github.com/lqqyt2423/go-mitmproxy/tracing"
	do "github.com/samber/do/v2"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelJaegerBackend "go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otelPrometheusBackend "go.opentelemetry.io/otel/exporters/prometheus"
	otelZipkinBackend "go.opentelemetry.io/otel/exporters/zipkin"
	"go.opentelemetry.io/otel/propagation"
	otel_metric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	otel_resource "go.opentelemetry.io/otel/sdk/resource"
	otel_trace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

func otelTraced(h http.Handler, opts ...otelhttp.Option) http.Handler {
	return otelhttp.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = otelSpanWithAttirbutes(r)
		h.ServeHTTP(w, r)
	}), "", opts...)
} // end otelTraced()

func otelSpanWithAttirbutes(r *http.Request) *http.Request {
	ctx := r.Context()
	if span := trace.SpanFromContext(ctx); span != nil {
		var uu_id any = helper.ContextGetKey(ctx, "uuid")
		if uu_id == nil {
			uu_id = uuid.New().String()
			ctx = helper.ContextAddKey(ctx, "uuid", uu_id)
			r = r.WithContext(ctx)
		} // end if
		attrs := []attribute.KeyValue{attribute.String("uuid", fmt.Sprintf("%+v", uu_id))}
		if rid := r.Header.Get("X-Request-Id"); rid != "" {
			attrs = append(attrs, attribute.String("http.request_id", rid))
		} // end if
		span.SetAttributes(attrs...)
	} // end if
	return r
} // end otelSpanWithAttirbutes()

func otelSpanNameFormatter(r *http.Request) string {
	reqMethod := strings.ToUpper(r.Method)
	strHost := r.URL.Host
	if strHost == "" {
		if vUrl := helper.ContextGetKey(r.Context(), "request.url"); vUrl != nil {
			if u, b := vUrl.(*url.URL); b {
				strHost = u.Host
			} // end if
		} // end if
	} // end if
	return fmt.Sprintf("%s %s", reqMethod, strHost)
} // end otelSpanNameFormatter()

func initTracer(proxy *Proxy, opts mytracing.TracingOptions) error {
	var exp otel_trace.SpanExporter
	var err error
	switch opts.Type {
	case "jaeger":
		if opts.URL == "" {
			opts.URL = mytracing.DefaultJaegerTracingOptions().URL
		} // end if
		exp, err = otelJaegerBackend.New(otelJaegerBackend.WithCollectorEndpoint(otelJaegerBackend.WithEndpoint(opts.URL)))
	case "zipkin":
		if opts.URL == "" {
			opts.URL = mytracing.DefaultZipkinTracingOptions().URL
		} // end if
		exp, err = otelZipkinBackend.New(opts.URL)
	case "datadog":
		if opts.URL == "" {
			opts.URL = mytracing.DefaultDatadogTracingOptions().URL
		} // end if
		u, eU := url.Parse(opts.URL)
		if eU != nil {
			return eU
		} // end if
		otlpHeaders := map[string]string{}
		if DATADOG_API_KEY := os.Getenv("DATADOG_API_KEY"); DATADOG_API_KEY != "" {
			otlpHeaders["DD-API-KEY"] = DATADOG_API_KEY
		} else {
			otlpHeaders["DD-API-KEY"] = os.Getenv("DD_API_KEY")
		} // end if
		exp, err = otlptracehttp.New(context.Background(),
			otlptracehttp.WithEndpoint(u.Host),
			otlptracehttp.WithURLPath(u.Path),
			otlptracehttp.WithHeaders(otlpHeaders),
		)
	default:
		return fmt.Errorf("unsupported tracing backend ‘%+v’", opts.Type)
	} // end switch
	if err != nil {
		return err
	} // end if
	res, _ := otel_resource.New(context.Background(), otel_resource.WithAttributes(semconv.ServiceName(SERVICE_NAME), semconv.ServiceVersion(proxy.Version)))
	traceSampler := otel_trace.WithSampler(otel_trace.ParentBased(otel_trace.TraceIDRatioBased(1.0)))
	tp := otel_trace.NewTracerProvider(otel_trace.WithBatcher(exp), otel_trace.WithResource(res), traceSampler)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		logrus.Errorf("otel error: %v", err)
	}))
	logrus.WithField("type", opts.Type).WithField("endpoint", opts.URL).Infof("Tracer initialized")
	return nil
} // end initTracer()

func initMeter(proxy *Proxy, opts mymetrics.MetricsOptions) error {
	switch opts.Type {
	case "prometheus", "snmp", "datadog":

	default:
		return fmt.Errorf("unsupported metrics backend ‘%+v’", opts.Type)
	} // end switch
	ctx := context.Background()
	var reader otel_metric.Reader
	var errExp error
	meterOpts := []otel_metric.Option{}
	switch opts.Mode {
	case string(zmq.Pull):
		reader, errExp = otelPrometheusBackend.New()
		if opts.Type == "snmp" {
			intrv, errInterval := time.ParseDuration(opts.RefreshInterval)
			if errInterval != nil {
				return errInterval
			} // end if
			if intrv.Seconds() <= 0 {
				return fmt.Errorf("zero interval")
			} // end if
			manualReader := otel_metric.NewManualReader()
			do.Provide(proxy.injector, func(do.Injector) (*mymetrics.SNMPRecorder, error) {
				rec := mymetrics.NewSnmpRecorder(intrv)
				return &rec, nil
			})
			go (func() {
				recorder := do.MustInvoke[*mymetrics.SNMPRecorder](proxy.injector)
				for range time.Tick(intrv) {
					rm := &metricdata.ResourceMetrics{}
					if err := reader.Collect(ctx, rm); err != nil {
						logrus.Warnf("Collect error: %+v", err)
						continue
					} // end if
					recorder.OnTick(rm)
				} // end for
			})()
			meterOpts = append(meterOpts, otel_metric.WithReader(manualReader))
		} // end if
	case string(zmq.Push):
		if opts.Type == "snmp" {
			return fmt.Errorf("push mode not supported when using SNMP")
		} // end if
		var grpcexporter *otlpmetricgrpc.Exporter
		otlpHeaders := map[string]string{}
		if DATADOG_API_KEY := os.Getenv("DATADOG_API_KEY"); DATADOG_API_KEY != "" {
			otlpHeaders["DD-API-KEY"] = DATADOG_API_KEY
		} else {
			otlpHeaders["DD-API-KEY"] = os.Getenv("DD_API_KEY")
		} // end if
		if grpcexporter, errExp = otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithHeaders(otlpHeaders), otlpmetricgrpc.WithInsecure(), otlpmetricgrpc.WithEndpoint(opts.Addr)); grpcexporter != nil {
			readerOpts := []otel_metric.PeriodicReaderOption{}
			if opts.RefreshInterval != "" {
				intrvl, errIntrvl := time.ParseDuration(opts.RefreshInterval)
				if errIntrvl != nil {
					return errIntrvl
				} // end if
				readerOpts = append(readerOpts, otel_metric.WithInterval(intrvl))
			} // end if

			reader = otel_metric.NewPeriodicReader(grpcexporter, readerOpts...)
		} // end if
	default:
		return fmt.Errorf("unsupported mode ‘%+v’", opts.Mode)
	} // end switch
	if errExp != nil {
		return errExp
	} // end if
	res, _ := otel_resource.New(ctx, otel_resource.WithAttributes(semconv.ServiceName(SERVICE_NAME), semconv.ServiceVersion(proxy.Version)))
	meterOpts = append(meterOpts, otel_metric.WithReader(reader), otel_metric.WithResource(res))
	meterProvider := otel_metric.NewMeterProvider(meterOpts...)
	otel.SetMeterProvider(meterProvider)
	return nil
} // end initMeter()
