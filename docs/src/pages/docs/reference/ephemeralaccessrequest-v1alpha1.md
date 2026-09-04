---
title: EphemeralAccessRequest
description: Generated field reference for the served v1alpha1 API.
---

[CRD API reference](/docs/operator-api-reference) · Served version `v1alpha1`.

Required fields apply when their containing object is present. Defaults shown are API-server defaults; null requires `nullable`. Standard metadata follows [Kubernetes conventions](https://kubernetes.io/docs/concepts/overview/working-with-objects/). Status is controller-owned except documented decisions.

For workflows, see [operator guidance](/docs/operator), [approval](/docs/operator-plan-approval), [candidates](/docs/operator-candidates), and [ephemeral access](/docs/ephemeral-access).

## Spec

| Path | Definition |
| --- | --- |
| `spec` | **object; required.** One immutable runtime request for a bounded access bundle. |
| `spec` | **CEL:** {"message":"request spec is immutable","rule":"self == oldSelf"}. Evaluated with self at this path; oldSelf refers to the previous value on update. |
| `spec.accessPolicyRef` | **object; required.** EphemeralAccessPolicy in this namespace that defines the requested bundle. |
| `spec.accessPolicyRef.name` | **string; required.** Name of the referenced resource in the same namespace. **Constraints:** {"maxLength":253,"minLength":1}. |
| `spec.justification` | **string; optional.** Reason for requesting access; required when the policy demands it. **Constraints:** {"maxLength":2048,"nullable":true}. |
| `spec.requestedBy` | **object; required.** Kubernetes identity which created the request. The supplied Kyverno reference policy overwrites this from authenticated admission &#96;userInfo&#96;. |
| `spec.requestedBy.groups` | **array; optional.** Kubernetes groups recorded for this actor. **Default:** []. **Constraints:** {"maxItems":64}. |
| `spec.requestedBy.groups[]` | **string; item or branch.** Constraints on this array item, map value, or conditional schema. **Constraints:** {"maxLength":256,"minLength":1}. |
| `spec.requestedBy.uid` | **string; optional.** Optional Kubernetes user UID recorded by admission. **Constraints:** {"maxLength":128,"nullable":true}. |
| `spec.requestedBy.username` | **string; required.** Kubernetes username asserted for this actor; authenticated only when enforced by admission. **Constraints:** {"maxLength":512,"minLength":1}. |
| `spec.requestedDuration` | **string; optional.** Requested access duration; omission uses the access policy default. **Constraints:** {"maxLength":64,"nullable":true,"pattern":"^([0-9]+[smh])+$"}. |
| `spec.subject` | **object; required.** PostgreSQL role receiving the temporary memberships. |
| `spec.subject.role` | **string; required.** Existing PostgreSQL role receiving temporary access. **Constraints:** {"maxLength":63,"minLength":1}. |

## Status (read-only except decisions)

| Path | Definition |
| --- | --- |
| `status` | **object; optional.** Controller lifecycle state and approval decisions for an access request. **Constraints:** {"nullable":true}. |
| `status` | **CEL:** {"message":"resolvedAccess is write-once","rule":"!has(oldSelf.resolvedAccess) &#124;&#124; (has(self.resolvedAccess) &amp;&amp; self.resolvedAccess == oldSelf.resolvedAccess)"}. Evaluated with self at this path; oldSelf refers to the previous value on update. |
| `status` | **CEL:** {"message":"Approved=True and Denied=True are mutually exclusive","rule":"!(self.conditions.exists(c, c.type == 'Approved' &amp;&amp; c.status == 'True') &amp;&amp; self.conditions.exists(c, c.type == 'Denied' &amp;&amp; c.status == 'True'))"}. Evaluated with self at this path; oldSelf refers to the previous value on update. |
| `status` | **CEL:** {"message":"approval decisions are terminal","rule":"oldSelf.conditions.filter(c, (c.type == 'Approved' &#124;&#124; c.type == 'Denied') &amp;&amp; c.status == 'True').size() == 0 &#124;&#124; self.conditions.filter(c, (c.type == 'Approved' &#124;&#124; c.type == 'Denied') &amp;&amp; c.status == 'True') == oldSelf.conditions.filter(c, (c.type == 'Approved' &#124;&#124; c.type == 'Denied') &amp;&amp; c.status == 'True')"}. Evaluated with self at this path; oldSelf refers to the previous value on update. |
| `status` | **CEL:** {"message":"decision identity is write-once","rule":"!has(oldSelf.decidedBy) &#124;&#124; (has(self.decidedBy) &amp;&amp; self.decidedBy == oldSelf.decidedBy)"}. Evaluated with self at this path; oldSelf refers to the previous value on update. |
| `status` | **CEL:** {"message":"a terminal approval decision and decidedBy identity must be recorded together","rule":"self.conditions.exists(c, (c.type == 'Approved' &#124;&#124; c.type == 'Denied') &amp;&amp; c.status == 'True') == has(self.decidedBy)"}. Evaluated with self at this path; oldSelf refers to the previous value on update. |
| `status` | **CEL:** {"message":"request conditions must use a declared lifecycle or decision type","rule":"self.conditions.all(c, c.type in ['Approved', 'Denied', 'Resolved', 'Ready', 'Applied'])"}. Evaluated with self at this path; oldSelf refers to the previous value on update. |
| `status.activatedAt` | **string; optional.** Timestamp at which the requested access became active. **Constraints:** {"maxLength":64,"nullable":true}. |
| `status.approvalExpiresAt` | **string; optional.** Timestamp after which a pending approval is no longer actionable. **Constraints:** {"maxLength":64,"nullable":true}. |
| `status.conditions` | **array; optional.** Lifecycle observations and terminal Approved or Denied decisions. **Default:** []. **Constraints:** {"maxItems":8}. |
| `status.conditions[]` | **object; item or branch.** Constraints on this array item, map value, or conditional schema. |
| `status.conditions[].bundleHash` | **string; optional.** Digest of the membership bundle to which this decision applies. **Constraints:** {"maxLength":71,"nullable":true}. |
| `status.conditions[].grantedDuration` | **string; optional.** Access duration to which this decision applies. **Constraints:** {"maxLength":64,"nullable":true}. |
| `status.conditions[].lastTransitionTime` | **string; optional.** Timestamp of the last condition-state transition. **Constraints:** {"maxLength":64,"nullable":true}. |
| `status.conditions[].message` | **string; optional.** Human-readable explanation of the condition. **Constraints:** {"maxLength":2048,"nullable":true}. |
| `status.conditions[].reason` | **string; optional.** Machine-readable reason for the condition. **Constraints:** {"maxLength":128,"nullable":true}. |
| `status.conditions[].status` | **string; required.** Condition state, conventionally True, False, or Unknown. **Constraints:** {"maxLength":16,"minLength":1}. |
| `status.conditions[].type` | **string; required.** Lifecycle or decision condition name. **Constraints:** {"maxLength":32,"minLength":1}. |
| `status.decidedBy` | **object; optional.** Kubernetes identity which approved or denied the request. The supplied Kyverno reference policy overwrites this from authenticated admission &#96;userInfo&#96; in the same status update as the terminal decision. **Constraints:** {"nullable":true}. |
| `status.decidedBy.groups` | **array; optional.** Kubernetes groups recorded for this actor. **Default:** []. **Constraints:** {"maxItems":64}. |
| `status.decidedBy.groups[]` | **string; item or branch.** Constraints on this array item, map value, or conditional schema. **Constraints:** {"maxLength":256,"minLength":1}. |
| `status.decidedBy.uid` | **string; optional.** Optional Kubernetes user UID recorded by admission. **Constraints:** {"maxLength":128,"nullable":true}. |
| `status.decidedBy.username` | **string; required.** Kubernetes username asserted for this actor; authenticated only when enforced by admission. **Constraints:** {"maxLength":512,"minLength":1}. |
| `status.endedAt` | **string; optional.** Timestamp at which the request reached its terminal state. **Constraints:** {"maxLength":64,"nullable":true}. |
| `status.expiresAt` | **string; optional.** Timestamp at which active access must be revoked. **Constraints:** {"maxLength":64,"nullable":true}. |
| `status.lastError` | **string; optional.** Most recent controller error for this request. **Constraints:** {"maxLength":4096,"nullable":true}. |
| `status.phase` | **string; optional.** Current request lifecycle phase. **Default:** "Pending". **Constraints:** {"enum":["Pending","PendingApproval","Applying","Active","Revoking","Ended","Revoked","Cancelled","Denied","ApprovalExpired","Failed"]}. |
| `status.resolvedAccess` | **object; optional.** Write-once snapshot of the approved target, duration, and exact memberships. **Constraints:** {"nullable":true}. |
| `status.resolvedAccess.accessPolicyGeneration` | **integer; required.** Generation of the access policy resolved for this request. **Constraints:** {"format":"int64"}. |
| `status.resolvedAccess.accessPolicyUid` | **string; required.** UID of the access policy resolved for this request. **Constraints:** {"maxLength":128}. |
| `status.resolvedAccess.bundleEncoding` | **string; required.** Versioned encoding used to compute the canonical bundle digest. **Constraints:** {"maxLength":128}. |
| `status.resolvedAccess.bundleHash` | **string; required.** SHA-256 digest of the canonical target and membership bundle. **Constraints:** {"maxLength":71}. |
| `status.resolvedAccess.grantedDuration` | **string; required.** Resolved duration for which access is granted. **Constraints:** {"maxLength":64}. |
| `status.resolvedAccess.memberships` | **array; required.** Exact membership edges frozen for activation and revocation. **Constraints:** {"maxItems":32}. |
| `status.resolvedAccess.memberships[]` | **object; item or branch.** Constraints on this array item, map value, or conditional schema. |
| `status.resolvedAccess.memberships[].inherit` | **boolean; required.** Whether privileges from role memberships are inherited automatically. |
| `status.resolvedAccess.memberships[].member` | **string; required.** PostgreSQL role receiving the membership. **Constraints:** {"maxLength":63,"minLength":1}. |
| `status.resolvedAccess.memberships[].role` | **string; required.** Granted PostgreSQL role. **Constraints:** {"maxLength":63,"minLength":1}. |
| `status.resolvedAccess.targetDatabaseFingerprint` | **string; required.** SHA-256 fingerprint of resolved host, port, and database name. It binds activation and revocation to one database without persisting secrets. **Constraints:** {"maxLength":71}. |
| `status.resolvedAccess.targetPolicyGeneration` | **integer; required.** Generation of the target PostgresPolicy at resolution. **Constraints:** {"format":"int64"}. |
| `status.resolvedAccess.targetPolicyUid` | **string; required.** UID of the PostgresPolicy managing the resolved database. **Constraints:** {"maxLength":128}. |
| `status.retainedMemberships` | **array; optional.** Memberships retained because another active request or the base policy still requires them. **Default:** []. **Constraints:** {"maxItems":32}. |
| `status.retainedMemberships[]` | **object; item or branch.** Constraints on this array item, map value, or conditional schema. |
| `status.retainedMemberships[].inherit` | **boolean; required.** Whether privileges from role memberships are inherited automatically. |
| `status.retainedMemberships[].member` | **string; required.** PostgreSQL role receiving the membership. **Constraints:** {"maxLength":63,"minLength":1}. |
| `status.retainedMemberships[].role` | **string; required.** Granted PostgreSQL role. **Constraints:** {"maxLength":63,"minLength":1}. |

[Download the complete served OpenAPI schema](/crd-reference/ephemeralaccessrequest-v1alpha1.json) for structural composition and all Kubernetes extensions.

Generated with `crdgen --docs-dir`; edit the Rust schema descriptions to change this reference.
