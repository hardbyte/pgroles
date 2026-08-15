//! Watch-fed indexes for ephemeral access requests.
//!
//! The request controller and this index consume the same watcher stream. A
//! request therefore enters the index before its reconcile can activate access,
//! while finalizers keep deleted requests present until revocation completes.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use kube::ResourceExt;
use kube::runtime::reflector::ObjectRef;
use kube::runtime::watcher::Event;
use tokio::sync::Notify;

use crate::crd::EphemeralAccessRequest;

type NamespacedKey = (String, String);

/// How long a lookup waits for the initial watch sync before giving up.
///
/// `compose_effective_graph` calls into this index from the PostgresPolicy
/// reconciler *after* both database locks are held. An unbounded wait would
/// therefore keep a PostgreSQL advisory lock for as long as the request watch
/// stayed broken, stalling every replica and every policy sharing that
/// database rather than only the ephemeral paths. Failing the lookup instead
/// lets the reconcile unwind, drop its locks, and requeue with backoff.
const READY_TIMEOUT: Duration = Duration::from_secs(30);

/// The request watch had not completed its initial sync in time.
#[derive(Debug, thiserror::Error)]
#[error("ephemeral request index did not sync within {waited:?}")]
pub struct IndexNotReady {
    waited: Duration,
}

#[derive(Default)]
struct IndexState {
    objects: HashMap<ObjectRef<EphemeralAccessRequest>, Arc<EphemeralAccessRequest>>,
    by_access_policy_name: HashMap<NamespacedKey, HashSet<ObjectRef<EphemeralAccessRequest>>>,
    by_access_policy_uid: HashMap<NamespacedKey, HashSet<ObjectRef<EphemeralAccessRequest>>>,
    by_target_policy_uid: HashMap<NamespacedKey, HashSet<ObjectRef<EphemeralAccessRequest>>>,
}

impl IndexState {
    fn remove(&mut self, object_ref: &ObjectRef<EphemeralAccessRequest>) {
        let Some(request) = self.objects.remove(object_ref) else {
            return;
        };
        remove_ref(
            &mut self.by_access_policy_name,
            &namespaced_key(&request, &request.spec.access_policy_ref.name),
            object_ref,
        );
        if let Some(resolved) = request
            .status
            .as_ref()
            .and_then(|status| status.resolved_access.as_ref())
        {
            remove_ref(
                &mut self.by_access_policy_uid,
                &namespaced_key(&request, &resolved.access_policy_uid),
                object_ref,
            );
            remove_ref(
                &mut self.by_target_policy_uid,
                &namespaced_key(&request, &resolved.target_policy_uid),
                object_ref,
            );
        }
    }

    fn upsert(&mut self, request: &EphemeralAccessRequest) {
        let object_ref = ObjectRef::from_obj(request);
        self.remove(&object_ref);
        let request = Arc::new(request.clone());
        self.by_access_policy_name
            .entry(namespaced_key(
                &request,
                &request.spec.access_policy_ref.name,
            ))
            .or_default()
            .insert(object_ref.clone());
        if let Some(resolved) = request
            .status
            .as_ref()
            .and_then(|status| status.resolved_access.as_ref())
        {
            self.by_access_policy_uid
                .entry(namespaced_key(&request, &resolved.access_policy_uid))
                .or_default()
                .insert(object_ref.clone());
            self.by_target_policy_uid
                .entry(namespaced_key(&request, &resolved.target_policy_uid))
                .or_default()
                .insert(object_ref.clone());
        }
        self.objects.insert(object_ref, request);
    }

    fn values_for(
        &self,
        index: &HashMap<NamespacedKey, HashSet<ObjectRef<EphemeralAccessRequest>>>,
        key: &NamespacedKey,
    ) -> Vec<Arc<EphemeralAccessRequest>> {
        index
            .get(key)
            .into_iter()
            .flatten()
            .filter_map(|object_ref| self.objects.get(object_ref).cloned())
            .collect()
    }
}

fn namespaced_key(request: &EphemeralAccessRequest, value: &str) -> NamespacedKey {
    (request.namespace().unwrap_or_default(), value.to_string())
}

fn remove_ref(
    index: &mut HashMap<NamespacedKey, HashSet<ObjectRef<EphemeralAccessRequest>>>,
    key: &NamespacedKey,
    object_ref: &ObjectRef<EphemeralAccessRequest>,
) {
    let remove_key = if let Some(refs) = index.get_mut(key) {
        refs.remove(object_ref);
        refs.is_empty()
    } else {
        false
    };
    if remove_key {
        index.remove(key);
    }
}

/// An atomically refreshed, watch-fed request index.
#[derive(Clone, Default)]
pub struct RequestIndex {
    live: Arc<RwLock<IndexState>>,
    initializing: Arc<RwLock<Option<IndexState>>>,
    ready: Arc<AtomicBool>,
    ready_notify: Arc<Notify>,
}

impl RequestIndex {
    /// Observe one event before it is passed to the controller reflector.
    pub fn observe(&self, event: &Event<EphemeralAccessRequest>) {
        match event {
            Event::Apply(request) => self
                .live
                .write()
                .expect("request index poisoned")
                .upsert(request),
            Event::Delete(request) => self
                .live
                .write()
                .expect("request index poisoned")
                .remove(&ObjectRef::from_obj(request)),
            Event::Init => {
                *self.initializing.write().expect("request index poisoned") =
                    Some(IndexState::default());
            }
            Event::InitApply(request) => {
                if let Some(buffer) = self
                    .initializing
                    .write()
                    .expect("request index poisoned")
                    .as_mut()
                {
                    buffer.upsert(request);
                }
            }
            Event::InitDone => {
                if let Some(buffer) = self
                    .initializing
                    .write()
                    .expect("request index poisoned")
                    .take()
                {
                    *self.live.write().expect("request index poisoned") = buffer;
                }
                self.ready.store(true, Ordering::Release);
                self.ready_notify.notify_waiters();
            }
        }
    }

    async fn wait_ready(&self) -> Result<(), IndexNotReady> {
        let synced = async {
            while !self.ready.load(Ordering::Acquire) {
                // Register interest before re-checking, so an InitDone landing
                // between the check and the await is not a lost wakeup.
                let notified = self.ready_notify.notified();
                if self.ready.load(Ordering::Acquire) {
                    break;
                }
                notified.await;
            }
        };
        tokio::time::timeout(READY_TIMEOUT, synced)
            .await
            .map_err(|_| IndexNotReady {
                waited: READY_TIMEOUT,
            })
    }

    pub async fn for_access_policy_name(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Vec<Arc<EphemeralAccessRequest>>, IndexNotReady> {
        self.wait_ready().await?;
        let state = self.live.read().expect("request index poisoned");
        Ok(state.values_for(
            &state.by_access_policy_name,
            &(namespace.to_string(), name.to_string()),
        ))
    }

    pub async fn for_access_policy_uid(
        &self,
        namespace: &str,
        uid: &str,
    ) -> Result<Vec<Arc<EphemeralAccessRequest>>, IndexNotReady> {
        self.wait_ready().await?;
        let state = self.live.read().expect("request index poisoned");
        Ok(state.values_for(
            &state.by_access_policy_uid,
            &(namespace.to_string(), uid.to_string()),
        ))
    }

    pub async fn for_target_policy_uid(
        &self,
        namespace: &str,
        uid: &str,
    ) -> Result<Vec<Arc<EphemeralAccessRequest>>, IndexNotReady> {
        self.wait_ready().await?;
        let state = self.live.read().expect("request index poisoned");
        Ok(state.values_for(
            &state.by_target_policy_uid,
            &(namespace.to_string(), uid.to_string()),
        ))
    }

    pub fn len(&self) -> usize {
        self.live
            .read()
            .expect("request index poisoned")
            .objects
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        DecisionActor, EphemeralAccessRequestSpec, EphemeralAccessRequestStatus,
        EphemeralAccessSubject, LocalObjectReference, ResolvedEphemeralAccess,
    };

    fn request(
        name: &str,
        access_name: &str,
        access_uid: &str,
        target_uid: &str,
    ) -> EphemeralAccessRequest {
        let mut request = EphemeralAccessRequest::new(
            name,
            EphemeralAccessRequestSpec {
                access_policy_ref: LocalObjectReference {
                    name: access_name.into(),
                },
                subject: EphemeralAccessSubject {
                    role: "alice".into(),
                },
                requested_by: DecisionActor {
                    username: "user".into(),
                    uid: None,
                    groups: vec![],
                },
                requested_duration: None,
                justification: None,
            },
        );
        request.metadata.namespace = Some("ns".into());
        if !access_uid.is_empty() {
            request.status = Some(EphemeralAccessRequestStatus {
                resolved_access: Some(ResolvedEphemeralAccess {
                    access_policy_uid: access_uid.into(),
                    access_policy_generation: 1,
                    target_policy_uid: target_uid.into(),
                    target_policy_generation: 1,
                    target_database_fingerprint: "sha256:test".into(),
                    granted_duration: "1h".into(),
                    bundle_encoding: "test".into(),
                    bundle_hash: "sha256:test".into(),
                    memberships: vec![],
                }),
                ..Default::default()
            });
        }
        request
    }

    #[tokio::test]
    async fn indexes_names_and_resolved_uids_and_replaces_on_restart() {
        let index = RequestIndex::default();
        let first = request("one", "access", "access-uid", "target-uid");
        index.observe(&Event::Init);
        index.observe(&Event::InitApply(first.clone()));
        index.observe(&Event::InitDone);
        assert_eq!(
            index
                .for_access_policy_name("ns", "access")
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            index
                .for_access_policy_uid("ns", "access-uid")
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            index
                .for_target_policy_uid("ns", "target-uid")
                .await
                .unwrap()
                .len(),
            1
        );

        index.observe(&Event::Init);
        index.observe(&Event::InitDone);
        assert_eq!(index.len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn lookups_fail_instead_of_hanging_when_the_watch_never_syncs() {
        // A request watch that never reaches InitDone previously blocked every
        // lookup forever. compose_effective_graph runs with both database locks
        // held, so that hang stranded a PostgreSQL advisory lock and wedged the
        // other replicas rather than failing this one reconcile.
        let index = RequestIndex::default();
        index.observe(&Event::Init);
        assert!(
            index
                .for_target_policy_uid("ns", "target-uid")
                .await
                .is_err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn lookups_unblock_as_soon_as_the_watch_syncs() {
        let index = RequestIndex::default();
        let waiter = {
            let index = index.clone();
            tokio::spawn(async move { index.for_access_policy_name("ns", "access").await })
        };
        tokio::task::yield_now().await;
        index.observe(&Event::Init);
        index.observe(&Event::InitApply(request("one", "access", "", "")));
        index.observe(&Event::InitDone);
        assert_eq!(waiter.await.expect("waiter panicked").unwrap().len(), 1);
    }

    #[tokio::test]
    async fn unresolved_requests_are_indexed_by_policy_name() {
        let index = RequestIndex::default();
        index.observe(&Event::Init);
        index.observe(&Event::InitApply(request("one", "access", "", "")));
        index.observe(&Event::InitDone);
        assert_eq!(
            index
                .for_access_policy_name("ns", "access")
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            index
                .for_access_policy_uid("ns", "access-uid")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn lookup_ignores_irrelevant_requests_and_forged_labels() {
        let index = RequestIndex::default();
        index.observe(&Event::Init);
        for sequence in 0..1_000 {
            let mut irrelevant = request(
                &format!("irrelevant-{sequence}"),
                "other-access",
                "other-access-uid",
                "other-target-uid",
            );
            irrelevant.metadata.namespace = Some(if sequence % 2 == 0 {
                "ns".into()
            } else {
                "other-ns".into()
            });
            index.observe(&Event::InitApply(irrelevant));
        }
        let mut relevant = request("relevant", "access", "access-uid", "target-uid");
        relevant.labels_mut().insert(
            crate::crd::LABEL_TARGET_POLICY_UID.into(),
            "forged-uid".into(),
        );
        index.observe(&Event::InitApply(relevant));
        index.observe(&Event::InitDone);

        let matches = index
            .for_target_policy_uid("ns", "target-uid")
            .await
            .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name_any(), "relevant");
        assert!(
            index
                .for_target_policy_uid("ns", "forged-uid")
                .await
                .unwrap()
                .is_empty()
        );
    }
}
