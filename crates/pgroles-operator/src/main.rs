//! pgroles-operator — Kubernetes controller for PostgresPolicy CRDs.
//!
//! Watches `PostgresPolicy` custom resources and reconciles PostgreSQL roles,
//! grants, default privileges, and memberships against live databases.

use std::sync::Arc;

use futures::StreamExt;
use kube::runtime::{Controller, WatchStreamExt, predicates, reflector, watcher};
use kube::{Api, Client};
use tracing::info;

use pgroles_operator::context::OperatorContext;
use pgroles_operator::crd::PostgresPolicy;
use pgroles_operator::observability::{OperatorObservability, serve_health};
use pgroles_operator::reconciler::{error_policy, reconcile};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .with_target(false)
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "starting pgroles-operator"
    );

    // Build kube client from in-cluster config or KUBECONFIG.
    let client = Client::try_default().await?;

    let observability = OperatorObservability::from_env()?;
    let http_addr = std::env::var("OPERATOR_HTTP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()?;
    let observability_server = observability.clone();
    tokio::spawn(async move {
        if let Err(error) = serve_health(http_addr, observability_server).await {
            tracing::error!(%error, %http_addr, "health server exited");
        }
    });

    // Create the shared operator context.
    let ctx = Arc::new(OperatorContext::new(client.clone(), observability.clone()));

    // Watch all PostgresPolicy resources across all namespaces.
    let policies: Api<PostgresPolicy> = Api::all(client);
    let (reader, writer) = reflector::store();
    let policy_stream = watcher(policies.clone(), watcher::Config::default())
        .default_backoff()
        .reflect(writer)
        .applied_objects()
        .predicate_filter(predicates::generation, Default::default());

    info!("starting controller");
    observability.mark_ready();

    Controller::for_stream(policy_stream, reader)
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|result| async move {
            match result {
                Ok(action) => {
                    tracing::debug!(?action, "reconcile completed");
                }
                Err(error) => {
                    tracing::error!(%error, "reconcile failed");
                }
            }
        })
        .await;

    observability.mark_not_ready();
    if let Err(error) = observability.shutdown() {
        tracing::warn!(%error, "failed to shut down observability");
    }
    info!("controller shut down");
    Ok(())
}
