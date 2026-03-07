---
title: CI/CD integration
description: Use pgroles as a drift gate in your CI/CD pipeline.
---

pgroles integrates into CI/CD pipelines as a drift gate, a deployment step, or both. {% .lead %}

---

## Drift detection

`pgroles diff --exit-code` returns specific exit codes for automation:

| Exit code | Meaning |
| --- | --- |
| `0` | Database is in sync with the manifest |
| `2` | Drift detected — roles, grants, or memberships differ |
| Other | Command or connectivity failure |

### GitHub Actions

Run drift detection on every PR to catch unexpected changes:

```yaml
jobs:
  drift-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install pgroles
        run: cargo install pgroles-cli

      - name: Check for drift
        run: pgroles diff -f pgroles.yaml --exit-code
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
```

### Apply on merge

Apply role changes automatically when manifests are merged to main:

```yaml
jobs:
  apply-roles:
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install pgroles
        run: cargo install pgroles-cli

      - name: Apply roles
        run: pgroles apply -f pgroles.yaml
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
```

### Diff as a PR comment

Post the planned SQL changes as a PR comment for review:

```yaml
      - name: Generate diff
        id: diff
        run: |
          OUTPUT=$(pgroles diff -f pgroles.yaml 2>&1) || true
          echo "diff<<EOF" >> "$GITHUB_OUTPUT"
          echo "$OUTPUT" >> "$GITHUB_OUTPUT"
          echo "EOF" >> "$GITHUB_OUTPUT"
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}

      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const diff = `${{ steps.diff.outputs.diff }}`;
            if (diff.trim()) {
              await github.rest.issues.createComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                issue_number: context.issue.number,
                body: `### pgroles diff\n\`\`\`sql\n${diff}\n\`\`\``
              });
            }
```

## Output formats

`pgroles diff` supports multiple output formats for different CI needs:

```shell
# Raw SQL (default) — human-readable, good for PR comments
pgroles diff -f pgroles.yaml

# JSON — machine-readable, good for programmatic processing
pgroles diff -f pgroles.yaml --format json

# Summary — high-level change counts
pgroles diff -f pgroles.yaml --format summary
```

## Docker-based pipelines

If your CI doesn't have Rust/Cargo, use the published Docker image:

```yaml
# GitLab CI
drift-check:
  image: ghcr.io/hardbyte/pgroles:latest
  script:
    - pgroles diff -f pgroles.yaml --exit-code
  variables:
    DATABASE_URL: $DATABASE_URL
```

```yaml
# GitHub Actions with Docker
- name: Check for drift
  run: |
    docker run --rm \
      -e DATABASE_URL="${{ secrets.DATABASE_URL }}" \
      -v ${{ github.workspace }}:/work \
      ghcr.io/hardbyte/pgroles:latest \
      diff -f /work/pgroles.yaml --exit-code
```

## Multiple environments

Manage staging and production with separate manifests or the same manifest against different databases:

```shell
# Staging
pgroles apply -f pgroles.yaml --database-url "$STAGING_DATABASE_URL"

# Production (same manifest, different database)
pgroles apply -f pgroles.yaml --database-url "$PROD_DATABASE_URL"
```

Or use environment-specific manifests if the role structures differ:

```
manifests/
  staging.yaml
  production.yaml
```
