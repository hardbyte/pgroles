---
title: EphemeralAccessPolicy
description: Generated field reference for the served v1alpha1 API.
---

[CRD API reference](/docs/operator-api-reference) · Served version `v1alpha1`.

Required fields apply when their containing object is present. Defaults shown are API-server defaults; null requires `nullable`. Standard metadata follows [Kubernetes conventions](https://kubernetes.io/docs/concepts/overview/working-with-objects/). Status is controller-owned except documented decisions.

For workflows, see [operator guidance](/docs/operator), [approval](/docs/operator-plan-approval), [candidates](/docs/operator-candidates), and [ephemeral access](/docs/ephemeral-access).

## Spec

| Path | Definition |
| --- | --- |
| ` spec ` | **object; required.** A GitOps-managed bundle of PostgreSQL memberships that may be requested. **Constraints:** ` {"required":["approval","justification","maximumDuration","memberships","postgresPolicyRef"]} `. |
| ` spec.approval ` | **object; required.** Whether activation requires a recorded approval decision. **Constraints:** ` {"required":["mode"]} `. |
| ` spec.approval.mode ` | **string; required.** Automatic activates without a human decision; Required waits for approval. **Constraints:** ` {"enum":["Automatic","Required"]} `. |
| ` spec.defaultDuration ` | **string; optional.** Duration used when a request omits requestedDuration; one of the two must be supplied. **Constraints:** ` {"maxLength":64,"nullable":true,"pattern":"^([0-9]+[smh])+$"} `. |
| ` spec.description ` | **string; optional.** Optional explanation of the access this policy provides. **Constraints:** ` {"maxLength":2048,"nullable":true} `. |
| ` spec.displayName ` | **string; optional.** Optional human-readable policy label. **Constraints:** ` {"maxLength":128,"nullable":true} `. |
| ` spec.justification ` | **object; required.** Whether requests must explain why access is needed. **Constraints:** ` {"required":["required"]} `. |
| ` spec.justification.required ` | **boolean; required.** Whether a request must include a non-empty justification. |
| ` spec.maximumDuration ` | **string; required.** Longest permitted access duration, using s, m, and h units. **Constraints:** ` {"maxLength":64,"pattern":"^([0-9]+[smh])+$"} `. |
| ` spec.memberships ` | **array; required.** Role memberships that this policy permits a subject to request. **Constraints:** ` {"maxItems":32,"minItems":1} `. |
| ` spec.memberships[] ` | **object; item or branch.** Constraints on this array item, map value, or conditional schema. **Constraints:** ` {"required":["inherit","role"]} `. |
| ` spec.memberships[].inherit ` | **boolean; required.** Whether privileges from role memberships are inherited automatically. |
| ` spec.memberships[].role ` | **string; required.** PostgreSQL role whose membership will be granted to the subject. **Constraints:** ` {"maxLength":63,"minLength":1} `. |
| ` spec.pendingRequestTTL ` | **string; optional.** Time allowed for a pending request to receive approval before it expires. **Default:** ` "15m" `. **Constraints:** ` {"maxLength":64,"pattern":"^([0-9]+[smh])+$"} `. |
| ` spec.postgresPolicyRef ` | **object; required.** PostgresPolicy in this namespace that manages the target database. **Constraints:** ` {"required":["name"]} `. |
| ` spec.postgresPolicyRef.name ` | **string; required.** Name of the referenced resource in the same namespace. **Constraints:** ` {"maxLength":253,"minLength":1} `. |
| ` spec.suspend ` | **boolean; optional.** Stops admission of new access through this policy while retaining revocation handling. **Default:** ` false `. |

## Status (read-only except decisions)

| Path | Definition |
| --- | --- |
| ` status ` | **object; optional.** Controller observations for an ephemeral access policy. **Constraints:** ` {"nullable":true} `. |
| ` status.conditions ` | **array; optional.** Controller observations about acceptance and readiness. **Default:** ` [] `. **Constraints:** ` {"maxItems":16} `. |
| ` status.conditions[] ` | **object; item or branch.** Constraints on this array item, map value, or conditional schema. **Constraints:** ` {"required":["status","type"]} `. |
| ` status.conditions[].bundleHash ` | **string; optional.** Digest of the membership bundle to which this decision applies. **Constraints:** ` {"maxLength":71,"nullable":true} `. |
| ` status.conditions[].grantedDuration ` | **string; optional.** Access duration to which this decision applies. **Constraints:** ` {"maxLength":64,"nullable":true} `. |
| ` status.conditions[].lastTransitionTime ` | **string; optional.** Timestamp of the last condition-state transition. **Constraints:** ` {"maxLength":64,"nullable":true} `. |
| ` status.conditions[].message ` | **string; optional.** Human-readable explanation of the condition. **Constraints:** ` {"maxLength":2048,"nullable":true} `. |
| ` status.conditions[].reason ` | **string; optional.** Machine-readable reason for the condition. **Constraints:** ` {"maxLength":128,"nullable":true} `. |
| ` status.conditions[].status ` | **string; required.** Condition state, conventionally True, False, or Unknown. **Constraints:** ` {"maxLength":16,"minLength":1} `. |
| ` status.conditions[].type ` | **string; required.** Lifecycle or decision condition name. **Constraints:** ` {"maxLength":32,"minLength":1} `. |
| ` status.observedGeneration ` | **integer; optional.** Policy generation last processed by the controller. **Constraints:** ` {"format":"int64","nullable":true} `. |
| ` status.resolvedRoles ` | **array; optional.** Validated PostgreSQL roles available through this policy. **Default:** ` [] `. **Constraints:** ` {"maxItems":32} `. |
| ` status.resolvedRoles[] ` | **string; item or branch.** Constraints on this array item, map value, or conditional schema. **Constraints:** ` {"maxLength":63,"minLength":1} `. |

[Download the complete served OpenAPI schema](/crd-reference/ephemeralaccesspolicy-v1alpha1.json) for structural composition and all Kubernetes extensions.

Generated with `crdgen --docs-dir`; edit the Rust schema descriptions to change this reference.
