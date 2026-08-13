//! Watch-fed indexes for ephemeral access requests.
//!
//! The request controller and this index consume the same watcher stream. A
//! request therefore enters the index before its reconcile can activate access,
//! while finalizers keep deleted requests present until revocation completes.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};

use kube::ResourceExt;
use kube::runtime::reflector::ObjectRef;
use kube::runtime::watcher::Event;
use tokio::sync::Notify;

use crate::crd::EphemeralAccessRequest;

type NamespacedKey = (String, String);

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

    async fn wait_ready(&self) {
        while !self.ready.load(Ordering::Acquire) {
            let notified = self.ready_notify.notified();
            if self.ready.load(Ordering::Acquire) {
                break;
            }
            notified.await;
        }
    }

    pub async fn for_access_policy_name(
        &self,
        namespace: &str,
        name: &str,
    ) -> Vec<Arc<EphemeralAccessRequest>> {
        self.wait_ready().await;
        let state = self.live.read().expect("request index poisoned");
        state.values_for(
            &state.by_access_policy_name,
            &(namespace.to_string(), name.to_string()),
        )
    }

    pub async fn for_access_policy_uid(
        &self,
        namespace: &str,
        uid: &str,
    ) -> Vec<Arc<EphemeralAccessRequest>> {
        self.wait_ready().await;
        let state = self.live.read().expect("request index poisoned");
        state.values_for(
            &state.by_access_policy_uid,
            &(namespace.to_string(), uid.to_string()),
        )
    }

    pub async fn for_target_policy_uid(
        &self,
        namespace: &str,
        uid: &str,
    ) -> Vec<Arc<EphemeralAccessRequest>> {
        self.wait_ready().await;
        let state = self.live.read().expect("request index poisoned");
        state.values_for(
            &state.by_target_policy_uid,
            &(namespace.to_string(), uid.to_string()),
        )
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
        EphemeralAccessActor, EphemeralAccessRequestSpec, EphemeralAccessRequestStatus,
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
                requested_by: EphemeralAccessActor {
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
        assert_eq!(index.for_access_policy_name("ns", "access").await.len(), 1);
        assert_eq!(
            index.for_access_policy_uid("ns", "access-uid").await.len(),
            1
        );
        assert_eq!(
            index.for_target_policy_uid("ns", "target-uid").await.len(),
            1
        );

        index.observe(&Event::Init);
        index.observe(&Event::InitDone);
        assert_eq!(index.len(), 0);
    }

    #[tokio::test]
    async fn unresolved_requests_are_indexed_by_policy_name() {
        let index = RequestIndex::default();
        index.observe(&Event::Init);
        index.observe(&Event::InitApply(request("one", "access", "", "")));
        index.observe(&Event::InitDone);
        assert_eq!(index.for_access_policy_name("ns", "access").await.len(), 1);
        assert!(
            index
                .for_access_policy_uid("ns", "access-uid")
                .await
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

        let matches = index.for_target_policy_uid("ns", "target-uid").await;
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name_any(), "relevant");
        assert!(
            index
                .for_target_policy_uid("ns", "forged-uid")
                .await
                .is_empty()
        );
    }
}
