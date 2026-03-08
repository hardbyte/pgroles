//! pgroles-operator — Kubernetes controller for PostgresPolicy CRDs.
//!
//! Watches `PostgresPolicy` custom resources and reconciles PostgreSQL roles,
//! grants, default privileges, and memberships against live databases.

use std::hash::{Hash, Hasher};
use std::sync::Arc;

use futures::{StreamExt, stream};
use k8s_openapi::api::core::v1::Secret;
use kube::runtime::events::{Recorder, Reporter};
use kube::runtime::reflector::ObjectRef;
use kube::runtime::{Controller, WatchStreamExt, predicates, reflector, watcher};
use kube::{Api, Client, Resource, ResourceExt};
use tracing::info;

use pgroles_operator::context::OperatorContext;
use pgroles_operator::crd::PostgresPolicy;
use pgroles_operator::observability::{OperatorObservability, serve_health};
use pgroles_operator::reconciler::{error_policy, reconcile};

fn policy_trigger_hash(policy: &PostgresPolicy) -> Option<u64> {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    policy.meta().generation.hash(&mut hasher);
    policy
        .meta()
        .deletion_timestamp
        .as_ref()
        .map(|timestamp| timestamp.0.to_string())
        .hash(&mut hasher);
    policy.meta().finalizers.hash(&mut hasher);
    Some(hasher.finish())
}

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

    let event_recorder = Recorder::new(
        client.clone(),
        Reporter {
            controller: "pgroles-operator".to_string(),
            instance: std::env::var("CONTROLLER_POD_NAME").ok(),
        },
    );

    // Create the shared operator context.
    let ctx = Arc::new(OperatorContext::new(
        client.clone(),
        observability.clone(),
        event_recorder,
    ));

    // Watch all PostgresPolicy resources across all namespaces.
    let policies: Api<PostgresPolicy> = Api::all(client.clone());
    let (reader, writer) = reflector::store();
    let policy_stream = watcher(policies.clone(), watcher::Config::default())
        .default_backoff()
        .reflect(writer)
        .applied_objects()
        .predicate_filter(policy_trigger_hash, Default::default());
    let policy_store = reader.clone();
    let secret_triggers = watcher(Api::<Secret>::all(client), watcher::Config::default())
        .default_backoff()
        .touched_objects()
        .predicate_filter(predicates::resource_version, Default::default())
        .filter_map(|secret| async move { secret.ok() })
        .flat_map(move |secret| {
            let policy_store = policy_store.clone();
            let Some(secret_ns) = secret.namespace() else {
                return stream::iter(Vec::<ObjectRef<PostgresPolicy>>::new());
            };
            let secret_name = secret.name_any();
            let refs = policy_store
                .state()
                .into_iter()
                .filter(|policy| {
                    policy.namespace().as_deref() == Some(secret_ns.as_str())
                        && policy.spec.connection.secret_ref.name == secret_name
                })
                .map(|policy| ObjectRef::from_obj(policy.as_ref()))
                .collect::<Vec<_>>();
            stream::iter(refs)
        });

    info!("starting controller");
    observability.mark_ready();

    Controller::for_stream(policy_stream, reader)
        .reconcile_on(secret_triggers)
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

#[cfg(test)]
mod tests {
    use super::policy_trigger_hash;
    use pgroles_operator::crd::{
        ConnectionSpec, PostgresPolicy, PostgresPolicySpec, SecretReference,
    };

    fn test_policy() -> PostgresPolicy {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: SecretReference {
                    name: "db-credentials".to_string(),
                },
                secret_key: "DATABASE_URL".to_string(),
            },
            interval: "5m".to_string(),
            suspend: false,
            default_owner: None,
            profiles: Default::default(),
            schemas: Vec::new(),
            roles: Vec::new(),
            grants: Vec::new(),
            default_privileges: Vec::new(),
            memberships: Vec::new(),
            retirements: Vec::new(),
        };
        let mut policy = PostgresPolicy::new("example", spec);
        policy.metadata.namespace = Some("default".to_string());
        policy.metadata.generation = Some(1);
        policy
    }

    #[test]
    fn policy_trigger_hash_changes_when_generation_changes() {
        let policy = test_policy();
        let original = policy_trigger_hash(&policy);

        let mut changed = policy.clone();
        changed.metadata.generation = Some(2);

        assert_ne!(original, policy_trigger_hash(&changed));
    }

    #[test]
    fn policy_trigger_hash_changes_when_finalizers_change() {
        let policy = test_policy();
        let original = policy_trigger_hash(&policy);

        let mut changed = policy.clone();
        changed.metadata.finalizers = Some(vec!["pgroles.io/finalizer".to_string()]);

        assert_ne!(original, policy_trigger_hash(&changed));
    }
}
