# plugin-k8s-opres-policies

OPA/Rego policy bundle for the [plugin-kubernetes](https://github.com/compliance-framework/plugin-k8s) plugin.
Evaluates operational resilience (OpRes) compliance for Kubernetes workloads across single and multi-cluster deployments.

## Policies

### `k8s_az_coverage` — Kubernetes AZ Coverage Check

Verifies that application pods are distributed across the required Availability Zones and/or regions globally across all configured clusters.

AZ discovery uses node labels:
- `topology.kubernetes.io/zone` (current standard)
- `failure-domain.beta.kubernetes.io/zone` (legacy fallback)

Region is taken from the cluster's `region` field in the plugin configuration (set explicitly for EKS clusters; optional for kubeconfig clusters).

App identity is derived from the pod label `app.kubernetes.io/name` by default, scoped per namespace.

---

## Policy Input Reference

All fields are passed via the `policy_input` config key in the CCF agent configuration and are merged into the Rego `input` document at the top level.

| Field | Type | Default | Description |
|---|---|---|---|
| `expected_azs` | `string[]` | `[]` | Explicit list of AZ names every app must be present in across all clusters |
| `expected_regions` | `string[]` | `[]` | Explicit list of region names every app must be present in across all clusters |
| `min_azs` | `number` | `0` | Minimum number of distinct AZs each app must span globally (0 = disabled) |
| `min_regions` | `number` | `0` | Minimum number of distinct regions each app must span globally (0 = disabled) |
| `app_label` | `string` | `"app.kubernetes.io/name"` | Pod label key used to identify the application name |

At least one criterion must be set (`expected_azs`, `expected_regions`, `min_azs`, or `min_regions`), otherwise a violation is raised.

### Criteria behaviour

- **`expected_azs`** and **`expected_regions`** are _membership_ checks — every discovered app must have at least one pod in each listed AZ/region. One violation is raised per app per missing AZ/region.
- **`min_azs`** and **`min_regions`** are _count_ checks — every discovered app must span at least N distinct AZs/regions globally across all clusters. One violation is raised per app that falls below the threshold, with the actual covered set listed in the message.
- All four criteria can be combined. Violations are raised independently per criterion.
- AZ/region counts are **global** — pods across all clusters are pooled. An app with pods in `us-east-1a` (cluster A) and `us-east-1b` (cluster B) spans 2 AZs globally.
- Clusters without a `region` set (e.g. local kubeconfig clusters) contribute AZs but **not** regions. Apps on such clusters will have `0` regions counted.

---

## Configuration Examples

### Minimum 2 AZs per app (single cluster)

```json
{
  "policy_input": "{\"min_azs\": 2}"
}
```

### Explicit required AZs (original behaviour)

```json
{
  "policy_input": "{\"expected_azs\": [\"us-east-1a\", \"us-east-1b\", \"us-east-1c\"]}"
}
```

### Minimum 2 regions (multi-cluster)

```json
{
  "policy_input": "{\"min_regions\": 2}"
}
```

### Required specific regions

```json
{
  "policy_input": "{\"expected_regions\": [\"us-east-1\", \"eu-west-1\"]}"
}
```

### Combined: minimum counts + required region

```json
{
  "policy_input": "{\"min_azs\": 3, \"min_regions\": 2, \"expected_regions\": [\"us-east-1\"]}"
}
```

This ensures every app:
- spans at least 3 distinct AZs globally
- spans at least 2 distinct regions globally
- is present in `us-east-1` specifically

### Custom app label

```json
{
  "policy_input": "{\"min_azs\": 2, \"app_label\": \"app\"}"
}
```

---

## Full CCF Agent Config Example

### Multi-cluster EKS (production)

```yaml
plugins:
  kubernetes:
    schedule: "*/5 * * * *"
    source: ghcr.io/compliance-framework/plugin-k8s:latest
    policies:
      - ghcr.io/compliance-framework/plugin-k8s-opres-policies:latest
    config:
      clusters: >
        [
          {"name":"prod-east","region":"us-east-1","cluster_name":"prod-east-eks"},
          {"name":"prod-west","region":"us-west-2","cluster_name":"prod-west-eks"},
          {"name":"prod-eu",  "region":"eu-west-1","cluster_name":"prod-eu-eks"}
        ]
      resources: '["nodes","pods"]'
      policy_input: '{"min_azs":3,"min_regions":2,"expected_regions":["us-east-1","eu-west-1"]}'
    labels:
      environment: production
      team: platform
```

### Local kind cluster (development)

```yaml
plugins:
  kubernetes:
    schedule: "* * * * *"
    source: ghcr.io/compliance-framework/plugin-k8s:latest
    policies:
      - /policies/k8s_policies.tar.gz
    config:
      clusters: '[{"name":"kind","region":"local","provider":"kubeconfig","kubeconfig":"/kubeconfig","context":"kind-local"}]'
      resources: '["nodes","pods"]'
      policy_input: '{"min_azs":1,"min_regions":1}'
    labels:
      environment: local
```

---

## Violations Reference

| Violation | Trigger |
|---|---|
| `App "X" has no pods in required AZ <az>` | App missing from an `expected_azs` entry |
| `App "X" has no pods in required region <region>` | App missing from an `expected_regions` entry |
| `App "X" spans only N AZ(s) (covered: [...]), minimum required is M` | App below `min_azs` threshold |
| `App "X" spans only N region(s) (covered: [...]), minimum required is M` | App below `min_regions` threshold |
| `Cluster "C": pod "P" (app=X) on node "N" has no AZ label` | Pod's node has neither AZ label |
| `No compliance criteria configured in policy_input (...)` | None of the four criteria are set |
| `No cluster data available` | `input.clusters` is empty or missing |

---

## Building

```bash
make test    # run OPA tests
make build   # outputs dist/bundle.tar.gz
```
