---
title: The PostgresPolicy resource
description: "The PostgresPolicy spec: policy sections, execution mode, approval, scheduling, and role passwords."
---

What goes in a `PostgresPolicy`, field by field. {% .lead %}

---

## Custom resource

A `PostgresPolicy` declares the roles, memberships, schemas, grants, and default
privileges pgroles should converge the database to, plus Kubernetes-specific
fields for connection and scheduling. Those policy sections are the same ones the
CLI manifest uses, so the [manifest guide](/docs/manifest-format) and
[manifest reference](/docs/manifest-reference) describe them field by field —
under `spec:` rather than at the top level.

The example below uses a connection URL Secret; see
[Database connection](/docs/operator-connections) for structured parameter support
(Zalando, CloudNativePG, PGO).

The custom resources use short names in `kubectl`: `pgr` for `PostgresPolicy`,
`pgplan` for `PostgresPolicyPlan`, `pgeap` for `EphemeralAccessPolicy`, and
`pgear` for `EphemeralAccessRequest`.

```yaml
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicy
metadata:
  name: myapp-roles
  namespace: default
spec:
  connection:
    secretRef:
      name: mydb-credentials
    secretKey: DATABASE_URL  # optional, defaults to DATABASE_URL

  interval: "5m"   # reconciliation interval (supports 5m, 1h, 30s, 1h30m)
  suspend: false   # set true to pause reconciliation
  mode: apply      # apply changes, or use plan for non-mutating drift preview
  approval: auto   # auto applies immediately; manual gates behind a reviewed plan
  reconciliation_mode: authoritative  # authoritative | additive | adopt

  default_owner: app_owner

  profiles:
    editor:
      login: false
      inherit: false
      grants:
        - privileges: [USAGE]
          object: { type: schema }
        - privileges: [SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER]
          object: { type: table, name: "*" }
        - privileges: [USAGE, SELECT, UPDATE]
          object: { type: sequence, name: "*" }
        - privileges: [EXECUTE]
          object: { type: function, name: "*" }
      default_privileges:
        - privileges: [SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER]
          on_type: table
        - privileges: [USAGE, SELECT, UPDATE]
          on_type: sequence
        - privileges: [EXECUTE]
          on_type: function

  schemas:
    - name: inventory
      owner: app_owner
      profiles: [editor]

  roles:
    - name: app-service
      login: true
      comment: "Application service account"
      config:
        search_path: inventory
        statement_timeout: "30s"   # config values are always strings

  grants:
    - role: app-service
      privileges: [CONNECT]
      object: { type: database, name: mydb }

  memberships:
    - role: inventory-editor
      members:
        - name: app-service

  retirements:
    - role: legacy_app
      reassign_owned_to: app_owner
      drop_owned: true
```

Declared schemas can be created and have ownership converged by the operator. Schemas that are only referenced from top-level grants or default privileges must already exist in the database. Profile-generated roles also inherit the profile-level `login` and `inherit` attributes shown above.

## Role passwords

Roles can either sync a password from an existing Kubernetes Secret or ask the operator to generate and manage a per-role Secret. In both cases the password value is resolved at reconcile time and only sent to PostgreSQL inside the apply transaction.

### Sync from an existing Secret

```yaml
spec:
  roles:
    - name: app-service
      login: true
      password:
        secretRef:
          name: app-passwords
        secretKey: app-service      # optional, defaults to the role name
      password_valid_until: "2026-12-31T00:00:00Z"
```

- `password.secretRef.name` — the Secret containing the password value.
- `password.secretKey` — the key within the Secret. Defaults to the role name if omitted.
- `password_valid_until` — ISO 8601 timestamp for PostgreSQL `VALID UNTIL`.

### Generate and manage a Secret

```yaml
spec:
  roles:
    - name: app-service
      login: true
      password:
        generate:
          length: 48                # optional, must be 16-128
          secretName: app-service-password   # optional
          secretKey: password       # optional, defaults to password
```

- `password.generate.length` — generated password length. Defaults to `32`. Must be between `16` and `128`.
- `password.generate.secretName` — override the generated Secret name. If omitted, the operator derives a Kubernetes-safe name from `{policy}-pgr-{role}`.
- `password.generate.secretKey` — key written into the generated Secret. Defaults to `password`.

Generated Secrets are created in the same namespace as the `PostgresPolicy`, owned by that policy, and include both the cleartext password and a SCRAM verifier. The cleartext password is written at `password.generate.secretKey` (default `password`) and the SCRAM verifier is written at the fixed key `verifier`. `password.generate.secretKey` must not be `verifier`; the CRD rejects that value. Deleting the generated Secret causes the operator to recreate it and rotate the PostgreSQL password on the next reconcile, reporting a `GeneratedSecretMissing` Warning Event as it does. The Secret is created only while an approved plan executes, so under `approval: manual` it appears when the plan applies, not when it is proposed.

### Validation and reconcile semantics

- Passwords are only allowed on roles with `login: true`.
- Exactly one of `password.secretRef` or `password.generate` must be set.
- Password values are redacted in operator logs and in the SQL preview stored on `PostgresPolicyPlan`.
- If the referenced Secret or key is missing, the operator sets `Ready=False` and `Degraded=True` with reason `SecretMissing` or `SecretFetchFailed`, and retries on the normal interval.
- Password updates are driven by password-source Secret changes. After a successful `apply`, unchanged password sources do not create permanent drift in later `plan` reconciles.
- pgroles cannot detect direct password changes made in PostgreSQL outside the operator, because PostgreSQL does not expose comparable password state safely.

The controller also emits Kubernetes Events for notable state transitions. These are intended for `kubectl describe` and quick operational debugging, not as a durable audit trail or alerting mechanism.

## Role configuration defaults

Roles can declare session defaults that PostgreSQL applies at login, managed via `ALTER ROLE ... SET`:

```yaml
spec:
  roles:
    - name: combined
    - name: blue
      login: true
      config:
        role: combined
    - name: green
      login: true
      config:
        role: combined

  memberships:
    - role: combined
      members:
        - name: blue
        - name: green
```

Config values are always strings in the CRD schema — quote numbers and booleans (`statement_timeout: "30000"`, `jit: "off"`); the API server rejects unquoted scalars at admission time. The `role: <group>` setting shown above implements blue/green credential rotation: both login roles switch to a shared owner role at connect, so objects created under either credential survive rotation. See [role configuration defaults](/docs/manifest-reference#role-configuration-defaults) in the manifest reference for semantics, reconciliation-mode behavior, and validation rules.

Note that this is distinct from `connection.params.setRole`, which controls the role the *operator's own connection* switches to; `roles[].config.role` controls what *managed application roles* switch to when they log in.
