//! pgpolicy-operator — Kubernetes controller for PostgresPolicy CRDs.
//!
//! Watches `PostgresPolicy` custom resources and reconciles PostgreSQL roles,
//! grants, default privileges, and memberships against live databases.

use std::sync::Arc;

use futures::StreamExt;
use kube::runtime::Controller;
use kube::{Api, Client};
use tracing::info;

use pgpolicy_operator::context::OperatorContext;
use pgpolicy_operator::crd::PostgresPolicy;
use pgpolicy_operator::reconciler::{error_policy, reconcile};

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
        "starting pgpolicy-operator"
    );

    // Build kube client from in-cluster config or KUBECONFIG.
    let client = Client::try_default().await?;

    // Create the shared operator context.
    let ctx = Arc::new(OperatorContext::new(client.clone()));

    // Watch all PostgresPolicy resources across all namespaces.
    let policies: Api<PostgresPolicy> = Api::all(client);

    info!("starting controller");

    Controller::new(policies, kube::runtime::watcher::Config::default())
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

    info!("controller shut down");
    Ok(())
}
