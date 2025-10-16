use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    metrics::SdkMeterProvider, resource::Resource, runtime::Tokio, trace, Resource as _,
};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

const DEFAULT_EXPORT_INTERVAL_SECS: u64 = 10;
const DEFAULT_EXPORT_TIMEOUT_MS: u64 = 5000;

#[derive(Default)]
pub struct TelemetryGuard {
    meter_provider: Option<SdkMeterProvider>,
    otel_enabled: bool,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if self.otel_enabled {
            // Flush traces before shutdown
            if let Err(err) = global::force_flush_tracer_provider() {
                eprintln!("failed to flush tracer provider: {err}");
            }
            global::shutdown_tracer_provider();

            if let Some(mut provider) = self.meter_provider.take() {
                if let Err(err) = provider.shutdown() {
                    eprintln!("failed to shutdown metrics provider: {err}");
                }
            }
        }
    }
}

pub fn init() -> TelemetryGuard {
    let json = std::env::var("CERBERE_LOG_JSON").ok().as_deref() == Some("1");
    let filter = EnvFilter::from_default_env();

    let otlp_endpoint = std::env::var("CERBERE_OTEL_ENDPOINT")
        .ok()
        .filter(|s| !s.is_empty());
    let service_name = std::env::var("CERBERE_SERVICE_NAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "cerbere".to_string());
    let export_interval = std::env::var("CERBERE_OTEL_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_EXPORT_INTERVAL_SECS);
    let export_timeout = std::env::var("CERBERE_OTEL_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_EXPORT_TIMEOUT_MS);

    let resource = Resource::new(vec![KeyValue::new("service.name", service_name)]);

    let fmt_layer = if json {
        fmt::layer().json().boxed()
    } else {
        fmt::layer().boxed()
    };

    let mut guard = TelemetryGuard::default();

    if let Some(endpoint) = otlp_endpoint {
        let trace_layer = build_trace_layer(&endpoint, &resource, export_timeout);
        let meter_provider =
            build_meter_provider(&endpoint, &resource, export_interval, export_timeout);

        let mut registry = tracing_subscriber::registry()
            .with(filter.clone())
            .with(fmt_layer.clone());

        if let Some(layer) = trace_layer {
            registry = registry.with(layer);
            guard.otel_enabled = true;
        }

        if let Some(provider) = meter_provider {
            global::set_meter_provider(provider.clone());
            guard.meter_provider = Some(provider);
            guard.otel_enabled = true;
        }

        let _ = registry.try_init();
    } else {
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .try_init();
    }

    guard
}

fn build_trace_layer(
    endpoint: &str,
    resource: &Resource,
    timeout_ms: u64,
) -> Option<
    tracing_opentelemetry::OpenTelemetryLayer<
        tracing_subscriber::Registry,
        opentelemetry_sdk::trace::Tracer,
    >,
> {
    use opentelemetry_sdk::trace::TracerProvider;

    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(endpoint.to_string())
        .with_timeout(std::time::Duration::from_millis(timeout_ms))
        .build_span_exporter()
        .map_err(|err| {
            eprintln!("failed to build OTLP span exporter: {err}");
            err
        })
        .ok()?;

    let batch_processor = trace::BatchSpanProcessor::builder(exporter, Tokio)
        .with_max_queue_size(4096)
        .with_scheduled_delay(std::time::Duration::from_millis(500))
        .build();

    let provider = trace::TracerProvider::builder()
        .with_resource(resource.clone())
        .with_span_processor(batch_processor)
        .build();

    let tracer = provider.tracer("cerbere");
    global::set_tracer_provider(provider.clone());

    Some(tracing_opentelemetry::layer().with_tracer(tracer))
}

fn build_meter_provider(
    endpoint: &str,
    resource: &Resource,
    interval_secs: u64,
    timeout_ms: u64,
) -> Option<SdkMeterProvider> {
    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(endpoint.to_string())
        .with_timeout(std::time::Duration::from_millis(timeout_ms))
        .build_metrics_exporter(opentelemetry_otlp::MetricsExporterConfig::default())
        .map_err(|err| {
            eprintln!("failed to build OTLP metrics exporter: {err}");
            err
        })
        .ok()?;

    let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter, Tokio)
        .with_interval(std::time::Duration::from_secs(interval_secs.max(1)))
        .build();

    Some(
        SdkMeterProvider::builder()
            .with_resource(resource.clone())
            .with_reader(reader)
            .build(),
    )
}
