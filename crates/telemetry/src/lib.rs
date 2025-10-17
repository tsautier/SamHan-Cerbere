use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    metrics::{MeterProvider, PeriodicReader},
    resource::Resource,
    runtime::Tokio,
    trace,
};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

const DEFAULT_EXPORT_INTERVAL_SECS: u64 = 10;
const DEFAULT_EXPORT_TIMEOUT_MS: u64 = 5000;

pub struct TelemetryGuard {
    meter_provider: Option<MeterProvider>,
    otel_enabled: bool,
}

impl Default for TelemetryGuard {
    fn default() -> Self {
        Self {
            meter_provider: None,
            otel_enabled: false,
        }
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if self.otel_enabled {
            global::shutdown_tracer_provider();

            if let Some(provider) = self.meter_provider.take() {
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

    if let Some(endpoint) = otlp_endpoint {
        init_with_otlp(
            json,
            filter,
            endpoint,
            resource,
            export_interval,
            export_timeout,
        )
    } else {
        init_without_otlp(json, filter)
    }
}

fn init_with_otlp(
    json: bool,
    filter: EnvFilter,
    endpoint: String,
    resource: Resource,
    export_interval: u64,
    export_timeout: u64,
) -> TelemetryGuard {
    let mut guard = TelemetryGuard::default();

    let tracer = init_tracer(&endpoint, &resource, export_timeout);
    let meter_provider =
        build_meter_provider(&endpoint, &resource, export_interval, export_timeout);

    if json {
        if let Some(tracer) = tracer.clone() {
            guard.otel_enabled = true;
            let registry = tracing_subscriber::registry()
                .with(filter.clone())
                .with(fmt::layer().json())
                .with(tracing_opentelemetry::layer().with_tracer(tracer));
            let _ = registry.try_init();
        } else {
            let registry = tracing_subscriber::registry()
                .with(filter.clone())
                .with(fmt::layer().json());
            let _ = registry.try_init();
        }
    } else if let Some(tracer) = tracer {
        guard.otel_enabled = true;
        let registry = tracing_subscriber::registry()
            .with(filter.clone())
            .with(fmt::layer())
            .with(tracing_opentelemetry::layer().with_tracer(tracer));
        let _ = registry.try_init();
    } else {
        let registry = tracing_subscriber::registry()
            .with(filter.clone())
            .with(fmt::layer());
        let _ = registry.try_init();
    }

    if let Some(provider) = meter_provider.clone() {
        global::set_meter_provider(provider);
        guard.otel_enabled = true;
    }

    guard.meter_provider = meter_provider;

    guard
}

fn init_without_otlp(json: bool, filter: EnvFilter) -> TelemetryGuard {
    if json {
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json())
            .try_init();
    } else {
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer())
            .try_init();
    }

    TelemetryGuard::default()
}

fn init_tracer(
    endpoint: &str,
    resource: &Resource,
    timeout_ms: u64,
) -> Option<opentelemetry_sdk::trace::Tracer> {
    use opentelemetry::trace::TracerProvider as _;

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

    let config = trace::Config::default().with_resource(resource.clone());
    let provider = trace::TracerProvider::builder()
        .with_config(config)
        .with_span_processor(batch_processor)
        .build();

    let tracer = provider.tracer("cerbere");
    global::set_tracer_provider(provider);

    Some(tracer)
}

fn build_meter_provider(
    endpoint: &str,
    resource: &Resource,
    interval_secs: u64,
    timeout_ms: u64,
) -> Option<MeterProvider> {
    use opentelemetry_sdk::metrics::reader::{
        DefaultAggregationSelector, DefaultTemporalitySelector,
    };

    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(endpoint.to_string())
        .with_timeout(std::time::Duration::from_millis(timeout_ms))
        .build_metrics_exporter(
            Box::new(DefaultAggregationSelector::new()),
            Box::new(DefaultTemporalitySelector::new()),
        )
        .map_err(|err| {
            eprintln!("failed to build OTLP metrics exporter: {err}");
            err
        })
        .ok()?;

    let reader = PeriodicReader::builder(exporter, Tokio)
        .with_interval(std::time::Duration::from_secs(interval_secs.max(1)))
        .build();

    let provider = MeterProvider::builder()
        .with_resource(resource.clone())
        .with_reader(reader)
        .build();

    Some(provider)
}
