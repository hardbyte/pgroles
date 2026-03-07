//! Operator health endpoints and OTLP metrics export.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Router, serve};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram, Meter, MeterProvider, UpDownCounter};
use opentelemetry_otlp::{MetricExporter, Protocol, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use tokio::net::TcpListener;

const SERVICE_NAME: &str = "pgroles-operator";

#[derive(Clone)]
pub struct OperatorObservability {
    ready: Arc<AtomicBool>,
    metrics: Option<Arc<Metrics>>,
}

struct Metrics {
    provider: SdkMeterProvider,
    reconcile_total: Counter<u64>,
    reconcile_duration_ms: Histogram<u64>,
    reconcile_inflight: UpDownCounter<i64>,
    lock_contention_total: Counter<u64>,
    policy_conflicts_total: Counter<u64>,
    invalid_spec_total: Counter<u64>,
    database_connection_failures_total: Counter<u64>,
    apply_total: Counter<u64>,
    apply_statements_total: Counter<u64>,
}

pub struct ReconcileGuard {
    metrics: Option<Arc<Metrics>>,
    started_at: Instant,
}

impl OperatorObservability {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            ready: Arc::new(AtomicBool::new(false)),
            metrics: init_metrics_from_env()?,
        })
    }

    pub fn mark_ready(&self) {
        self.ready.store(true, Ordering::Relaxed);
    }

    pub fn mark_not_ready(&self) {
        self.ready.store(false, Ordering::Relaxed);
    }

    pub fn start_reconcile(&self) -> ReconcileGuard {
        if let Some(metrics) = &self.metrics {
            metrics.reconcile_inflight.add(1, &[]);
            ReconcileGuard {
                metrics: Some(metrics.clone()),
                started_at: Instant::now(),
            }
        } else {
            ReconcileGuard {
                metrics: None,
                started_at: Instant::now(),
            }
        }
    }

    pub fn record_database_connection_failure(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.database_connection_failures_total.add(1, &[]);
        }
    }

    pub fn record_policy_conflict(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.policy_conflicts_total.add(1, &[]);
        }
    }

    pub fn record_lock_contention(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.lock_contention_total.add(1, &[]);
        }
    }

    pub fn record_invalid_spec(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.invalid_spec_total.add(1, &[]);
        }
    }

    pub fn record_apply_result(&self, result: &str) {
        if let Some(metrics) = &self.metrics {
            metrics
                .apply_total
                .add(1, &[KeyValue::new("result", result.to_string())]);
        }
    }

    pub fn record_apply_statements(&self, statements: usize) {
        if statements == 0 {
            return;
        }
        if let Some(metrics) = &self.metrics {
            metrics.apply_statements_total.add(statements as u64, &[]);
        }
    }

    pub fn shutdown(&self) -> anyhow::Result<()> {
        if let Some(metrics) = &self.metrics {
            metrics.provider.shutdown()?;
        }
        Ok(())
    }
}

impl ReconcileGuard {
    pub fn record_result(self, result: &str, reason: &str) {
        if let Some(metrics) = &self.metrics {
            metrics.reconcile_total.add(
                1,
                &[
                    KeyValue::new("result", result.to_string()),
                    KeyValue::new("reason", reason.to_string()),
                ],
            );
            metrics
                .reconcile_duration_ms
                .record(self.started_at.elapsed().as_millis() as u64, &[]);
        }
    }
}

impl Drop for ReconcileGuard {
    fn drop(&mut self) {
        if let Some(metrics) = &self.metrics {
            metrics.reconcile_inflight.add(-1, &[]);
        }
    }
}

pub async fn serve_health(
    bind_addr: SocketAddr,
    observability: OperatorObservability,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    let app = Router::new()
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        .with_state(observability);

    serve(listener, app).await?;
    Ok(())
}

fn init_metrics_from_env() -> anyhow::Result<Option<Arc<Metrics>>> {
    if !otel_metrics_enabled() {
        return Ok(None);
    }

    let exporter = MetricExporter::builder()
        .with_tonic()
        .with_protocol(Protocol::Grpc)
        .build()?;

    let reader = PeriodicReader::builder(exporter).build();
    let provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(
            Resource::builder_empty()
                .with_attributes([
                    KeyValue::new("service.name", SERVICE_NAME),
                    KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                ])
                .build(),
        )
        .build();

    let meter = provider.meter(SERVICE_NAME);
    Ok(Some(Arc::new(Metrics::new(provider, meter))))
}

fn otel_metrics_enabled() -> bool {
    let metrics_exporter = std::env::var("OTEL_METRICS_EXPORTER").ok();
    if matches!(metrics_exporter.as_deref(), Some("none")) {
        return false;
    }

    std::env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT").is_some()
        || std::env::var_os("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT").is_some()
}

impl Metrics {
    fn new(provider: SdkMeterProvider, meter: Meter) -> Self {
        Self {
            provider,
            reconcile_total: meter
                .u64_counter("pgroles.reconcile.total")
                .with_description("Total reconciliations by result and reason")
                .build(),
            reconcile_duration_ms: meter
                .u64_histogram("pgroles.reconcile.duration")
                .with_unit("ms")
                .with_description("Reconciliation duration in milliseconds")
                .build(),
            reconcile_inflight: meter
                .i64_up_down_counter("pgroles.reconcile.inflight")
                .with_description("In-flight reconciliations")
                .build(),
            lock_contention_total: meter
                .u64_counter("pgroles.lock_contention.total")
                .with_description("Reconciliations delayed by per-database lock contention")
                .build(),
            policy_conflicts_total: meter
                .u64_counter("pgroles.policy.conflicts")
                .with_description("Conflicting policies targeting the same database")
                .build(),
            invalid_spec_total: meter
                .u64_counter("pgroles.invalid_spec.total")
                .with_description("Invalid PostgresPolicy specifications")
                .build(),
            database_connection_failures_total: meter
                .u64_counter("pgroles.database.connection_failures")
                .with_description("Database connection failures during reconciliation")
                .build(),
            apply_total: meter
                .u64_counter("pgroles.apply.total")
                .with_description("Apply transaction outcomes")
                .build(),
            apply_statements_total: meter
                .u64_counter("pgroles.apply.statements")
                .with_description("SQL statements executed during successful applies")
                .build(),
        }
    }
}

async fn livez() -> &'static str {
    "ok"
}

async fn readyz(State(observability): State<OperatorObservability>) -> impl IntoResponse {
    if observability.ready.load(Ordering::Relaxed) {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use opentelemetry::metrics::MeterProvider;
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};

    use super::{
        Metrics, OperatorObservability, ReconcileGuard, SERVICE_NAME, livez, otel_metrics_enabled,
        readyz,
    };

    fn test_observability() -> (
        OperatorObservability,
        SdkMeterProvider,
        InMemoryMetricExporter,
    ) {
        let exporter = InMemoryMetricExporter::default();
        let provider = SdkMeterProvider::builder()
            .with_reader(PeriodicReader::builder(exporter.clone()).build())
            .build();
        let meter = provider.meter(SERVICE_NAME);
        let observability = OperatorObservability {
            ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            metrics: Some(Arc::new(Metrics::new(provider.clone(), meter))),
        };

        (observability, provider, exporter)
    }

    fn metric_exists(metrics: &[ResourceMetrics], name: &str) -> bool {
        metrics.iter().any(|resource_metrics| {
            resource_metrics
                .scope_metrics()
                .flat_map(|scope_metrics| scope_metrics.metrics())
                .any(|metric| metric.name() == name)
        })
    }

    fn u64_sum_value(metrics: &[ResourceMetrics], name: &str) -> Option<u64> {
        metrics
            .iter()
            .flat_map(|resource_metrics| resource_metrics.scope_metrics())
            .flat_map(|scope_metrics| scope_metrics.metrics())
            .find(|metric| metric.name() == name)
            .and_then(|metric| match metric.data() {
                AggregatedMetrics::U64(MetricData::Sum(sum)) => sum
                    .data_points()
                    .next()
                    .map(|data_point| data_point.value()),
                _ => None,
            })
    }

    fn i64_sum_value(metrics: &[ResourceMetrics], name: &str) -> Option<i64> {
        metrics
            .iter()
            .flat_map(|resource_metrics| resource_metrics.scope_metrics())
            .flat_map(|scope_metrics| scope_metrics.metrics())
            .find(|metric| metric.name() == name)
            .and_then(|metric| match metric.data() {
                AggregatedMetrics::I64(MetricData::Sum(sum)) => sum
                    .data_points()
                    .next()
                    .map(|data_point| data_point.value()),
                _ => None,
            })
    }

    #[test]
    fn otel_metrics_stay_disabled_without_endpoint() {
        unsafe {
            std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
            std::env::remove_var("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT");
            std::env::remove_var("OTEL_METRICS_EXPORTER");
        }
        assert!(!otel_metrics_enabled());
    }

    #[test]
    fn otel_metrics_enable_with_explicit_endpoint() {
        unsafe {
            std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317");
            std::env::remove_var("OTEL_METRICS_EXPORTER");
        }
        assert!(otel_metrics_enabled());
        unsafe {
            std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        }
    }

    #[tokio::test]
    async fn health_endpoints_reflect_readiness() {
        let (observability, _provider, _exporter) = test_observability();

        assert_eq!(livez().await, "ok");

        let not_ready = readyz(State(observability.clone())).await.into_response();
        assert_eq!(not_ready.status(), StatusCode::SERVICE_UNAVAILABLE);

        observability.mark_ready();
        let ready = readyz(State(observability)).await.into_response();
        assert_eq!(ready.status(), StatusCode::OK);
    }

    #[test]
    fn metrics_are_recorded_and_flushed() {
        let (observability, provider, exporter) = test_observability();

        let guard: ReconcileGuard = observability.start_reconcile();
        observability.record_lock_contention();
        observability.record_policy_conflict();
        observability.record_invalid_spec();
        observability.record_database_connection_failure();
        observability.record_apply_result("success");
        observability.record_apply_statements(4);
        guard.record_result("conflict", "ConflictingPolicy");

        provider.force_flush().expect("flush should succeed");

        let metrics = exporter
            .get_finished_metrics()
            .expect("metrics should be exported");

        assert!(metric_exists(&metrics, "pgroles.reconcile.total"));
        assert!(metric_exists(&metrics, "pgroles.reconcile.duration"));
        assert_eq!(
            u64_sum_value(&metrics, "pgroles.lock_contention.total"),
            Some(1)
        );
        assert_eq!(u64_sum_value(&metrics, "pgroles.policy.conflicts"), Some(1));
        assert_eq!(
            u64_sum_value(&metrics, "pgroles.invalid_spec.total"),
            Some(1)
        );
        assert_eq!(
            u64_sum_value(&metrics, "pgroles.database.connection_failures"),
            Some(1)
        );
        assert_eq!(u64_sum_value(&metrics, "pgroles.apply.statements"), Some(4));
        assert_eq!(
            i64_sum_value(&metrics, "pgroles.reconcile.inflight"),
            Some(0)
        );
    }
}
