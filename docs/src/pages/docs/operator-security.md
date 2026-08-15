---
title: Operator RBAC and security
description: The Kubernetes permissions the operator needs and its deployment security posture.
---

What the operator is allowed to do in your cluster. {% .lead %}

---

## RBAC

The operator requires a ClusterRole with these permissions:

| API group | Resource | Verbs |
| --- | --- | --- |
| `pgroles.io` | `postgrespolicies` | get, list, watch, patch, update |
| `pgroles.io` | `postgrespolicies/status` | get, patch, update |
| `pgroles.io` | `postgrespolicies/finalizers` | update |
| `pgroles.io` | `postgrespolicyplans` | get, list, watch, create, update, patch, delete |
| `pgroles.io` | `postgrespolicyplans/status` | get, patch, update |
| `pgroles.io` | `ephemeralaccesspolicies`, `ephemeralaccessrequests` | get, list, watch, patch, update, delete |
| `pgroles.io` | `ephemeralaccesspolicies/status`, `ephemeralaccessrequests/status` | get, patch, update |
| `pgroles.io` | `ephemeralaccesspolicies/finalizers`, `ephemeralaccessrequests/finalizers` | update |
| `pgroles.io` | `ephemeralaccesspolicies` | `manage` |
| `""` | `secrets` | get, list, watch, create, update, patch |
| `""` | `configmaps` | get, list, create, update, patch, delete |
| `events.k8s.io` | `events` | create, patch |

Every rule is load-bearing. `postgrespolicyplans` is required to apply anything
at all, because each apply goes through a plan; `configmaps` stores plan SQL
above the inline size limit. The `manage` verb is a logical permission with no
built-in meaning: admission policy uses it to authorize operator-owned request
lifecycle changes without hard-coding a service account identity, which is why
the operator holds it while holding neither `use` nor `approve`. See
[securing ephemeral access](/docs/ephemeral-access-security).

The Helm chart creates the ClusterRole, ClusterRoleBinding, and ServiceAccount
automatically. `charts/pgroles-operator/templates/clusterrole.yaml` is the source
of truth; check it against this table before hand-writing a role.
