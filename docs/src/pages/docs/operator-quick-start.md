---
title: Operator quick start
description: Install the pgroles Kubernetes operator, preview a safe additive policy, approve it, and verify the result.
---

Go from an empty Kubernetes namespace to a reviewed PostgreSQL change. {% .lead %}

---

This walkthrough creates one non-login PostgreSQL role and grants it `CONNECT`
on the target database. It uses additive reconciliation and manual approval, so
the operator neither revokes existing access nor executes the plan before you
approve it.

## Before you start

You need:

- a Kubernetes cluster and current `kubectl` context
- Helm 3 with access to `ghcr.io`
- a PostgreSQL database reachable from pods in the cluster
- a PostgreSQL credential that can inspect the database, create roles, and
  grant `CONNECT` on the target database

For a least-privilege production credential, follow
[executor privileges](/docs/executor-privileges). A database administrator
credential is fine for this first run against a disposable database.

Set two shell variables used throughout the walkthrough:

```bash
NAMESPACE=pgroles-quick-start
POLICY=quick-start
```

## 1. Install the operator

Install the chart into its own namespace and wait for the Deployment:

```bash
helm install pgroles-operator \
  oci://ghcr.io/hardbyte/charts/pgroles-operator \
  --namespace pgroles-system \
  --create-namespace \
  --wait

kubectl get pods -n pgroles-system \
  -l app.kubernetes.io/instance=pgroles-operator
```

The chart installs four CRDs: `PostgresPolicy`, `PostgresPolicyPlan`, and the
`EphemeralAccessPolicy` / `EphemeralAccessRequest` pair behind
[ephemeral access](/docs/ephemeral-access). The operator watches every namespace
unless `operator.watchNamespace` scopes it to one.

## 2. Add the database credential

Create the policy namespace, then enter the connection URL without putting it
in shell history or the process list:

```bash
kubectl create namespace "$NAMESPACE"

umask 077
credential_file="$(mktemp)"
trap 'rm -f "$credential_file"' EXIT
read -rsp 'Database URL: ' DATABASE_URL && printf '\n'
printf '%s' "$DATABASE_URL" > "$credential_file"
unset DATABASE_URL

kubectl create secret generic quick-start-database \
  --namespace "$NAMESPACE" \
  --from-file=DATABASE_URL="$credential_file"
```

Enter a URL such as `postgresql://pgroles_executor:password@db.example.com:5432/app`.
The host must resolve and be reachable from the operator pod. In production,
prefer a secret manager or CSI driver; see
[database connections](/docs/operator-connections) for structured credentials
and cloud IAM authentication.

## 3. Apply a non-destructive policy

Save this as `quick-start-policy.yaml`:

```yaml
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicy
metadata:
  name: quick-start
  namespace: pgroles-quick-start
spec:
  connection:
    secretRef:
      name: quick-start-database

  mode: apply
  approval: manual
  reconciliation_mode: additive
  interval: 5m

  roles:
    - name: pgroles_quickstart_reader
      login: false
      comment: Created by the pgroles operator quick start

  grants:
    - role: pgroles_quickstart_reader
      object: { type: database }
      privileges: [CONNECT]
```

```bash
kubectl apply -f quick-start-policy.yaml
kubectl wait --namespace "$NAMESPACE" \
  --for=condition=Ready "pgr/$POLICY" \
  --timeout=2m
kubectl get pgr "$POLICY" --namespace "$NAMESPACE"
```

The policy should report `MODE=apply`, `DRIFT=True`, and a non-zero change
count. `Ready=True` here means the plan was computed successfully; `Drift=True`
means it is waiting for approval.

## 4. Review the SQL

Follow the policy's `current_plan_ref` rather than guessing the generated plan
name:

```bash
PLAN="$(kubectl get pgr "$POLICY" --namespace "$NAMESPACE" \
  -o jsonpath='{.status.current_plan_ref.name}')"

kubectl get pgplan "$PLAN" --namespace "$NAMESPACE"
kubectl get pgplan "$PLAN" --namespace "$NAMESPACE" \
  -o jsonpath='{.status.sqlInline}'
printf '\n'
```

Expect a `CREATE ROLE` and `GRANT CONNECT`. Stop and inspect the policy if the
plan contains any revocation or drop. This example's additive mode should not
produce either.

## 5. Approve and verify

Approve exactly the plan you reviewed. The decision is a terminal condition on
the plan's status, written together with the identity that decided — the two
must land in one write, and neither can be changed afterwards:

```bash
kubectl patch pgplan "$PLAN" --namespace "$NAMESPACE" \
  --subresource=status --type=merge -p '{
    "status": {
      "conditions": [{
        "type": "Approved", "status": "True",
        "reason": "ApprovedByReviewer",
        "message": "reviewed change summary",
        "lastTransitionTime": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"
      }],
      "decidedBy": {"username": "'"$(kubectl auth whoami -o jsonpath='{.status.userInfo.username}')"'"}
    }
  }'

kubectl wait --namespace "$NAMESPACE" \
  --for=jsonpath='{.status.phase}'=Applied "pgplan/$PLAN" \
  --timeout=2m

kubectl get pgr "$POLICY" --namespace "$NAMESPACE"
kubectl get pgplan "$PLAN" --namespace "$NAMESPACE"
```

The policy should now show `DRIFT=False`; the plan phase should be `Applied`.
The operator re-inspects and re-renders before execution, so it will supersede
an approved plan rather than run it if the database diff changed during review.

To reject a plan instead, write `Denied` in place of `Approved`. The operator
moves the plan to `Rejected` and creates a fresh plan on the next reconcile:

```bash
kubectl patch pgplan "$PLAN" --namespace "$NAMESPACE" \
  --subresource=status --type=merge -p '{
    "status": {
      "conditions": [{
        "type": "Denied", "status": "True",
        "reason": "DeniedByReviewer",
        "message": "not approving this change",
        "lastTransitionTime": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"
      }],
      "decidedBy": {"username": "'"$(kubectl auth whoami -o jsonpath='{.status.userInfo.username}')"'"}
    }
  }'
```

A decision is terminal: it cannot be changed, reversed, or paired with the
opposite decision. Iterating means a new plan, not an edited decision.

{% callout type="warning" title="decidedBy is only as good as your admission layer" %}
The CRD's validation rules make a decision terminal and force it to carry a
`decidedBy`, but Kubernetes CEL cannot see the authenticated user, so the API
server cannot check that `decidedBy` names the account that actually wrote it —
above, you are typing your own username into the field.

Install the plan-decision admission policy to make it verified. It overwrites
`decidedBy` from the authenticated admission request and requires the `approve`
verb on the parent `PostgresPolicy`, so patching a plan's status is no longer by
itself authority to approve a database change. Without it, any account that can
patch `postgrespolicyplans/status` can approve, under any name it chooses.

With Kyverno 1.18 or later installed in the cluster, enable it through the
chart. The operator's exemption is generated from the values you installed
with, so a custom ServiceAccount name or namespace stays correct:

```shell
helm upgrade pgroles-operator oci://ghcr.io/hardbyte/charts/pgroles-operator \
  --namespace pgroles-system --reuse-values \
  --set admissionPolicies.enabled=true
```

For chart-less installs, `k8s/security/plan-decision-kyverno.yaml` is the same
policy pinned to the `pgroles-system` namespace and the `pgroles-operator`
ServiceAccount name; edit the exemption if yours differ.
{% /callout %}

## 6. Make a second change

Add another role or grant to `quick-start-policy.yaml`, apply it again, and
repeat the review and approval steps. Each new database diff gets its own
`PostgresPolicyPlan`.

When you are comfortable with the review loop, choose deliberately between:

- `approval: manual` for a human gate on every change
- `approval: auto` for continuous convergence without a human gate
- `mode: observe` for a permanently non-mutating drift preview

Read [plan and approval](/docs/operator-plan-approval) before changing those
controls. For an existing database, keep additive or follow
[staged adoption](/docs/adoption) before moving toward authoritative ownership.

## Cleanup

Deleting the Kubernetes resources stops reconciliation but deliberately leaves
the database unchanged:

```bash
kubectl delete pgr "$POLICY" --namespace "$NAMESPACE" --wait=true
kubectl delete namespace "$NAMESPACE"
helm uninstall pgroles-operator --namespace pgroles-system
kubectl delete namespace pgroles-system
```

The `pgroles_quickstart_reader` PostgreSQL role remains. Remove it separately as
a database administrator if this was only a test. Do not assume deleting a
`PostgresPolicy` rolls back SQL it previously applied.

If any step does not reach the expected state, use the
[operator troubleshooting index](/docs/operator-troubleshooting).
