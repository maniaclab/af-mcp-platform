# Adding a Backend MCP Server

The platform is designed so that adding the Nth backend requires **no code
changes** — only configuration. The five steps below are the complete procedure.

---

## Step 1 — Add the backend to the aggregator backend list

Edit the HelmRelease for the platform (typically
`clusters/<cluster>/af-mcp-platform/helmrelease.yaml`) and add one entry under
`values.aggregator.backends`:

```yaml
values:
  aggregator:
    backends:
      # existing backends omitted for brevity
      - name: my-new-backend
        url: http://my-new-backend.af-mcp-backends.svc.cluster.local:8000/mcp
        required_capability: my-new-backend:use
        timeout_seconds: 30
```

`required_capability` is the capability string the broker's Authorization
subsystem will check before forwarding any tool call to this backend.

---

## Step 2 — Ensure the capability exists in policy.yaml

Check `charts/af-mcp-platform/files/policy.yaml` (or the ConfigMap it renders
into). If `my-new-backend:use` is not already listed, add it:

```yaml
capabilities:
  # ...existing entries...
  - name: my-new-backend:use
    description: "Access to my-new-backend tools"
```

If the capability already exists (e.g., a generic `af:user` capability that covers
many backends), skip this step.

---

## Step 3 — Map the capability to Keycloak groups (if new)

If you added a new capability in Step 2, map it to one or more AF Keycloak groups
in the HelmRelease values:

```yaml
values:
  entitlements:
    group_capabilities:
      # existing mappings omitted
      af-my-new-backend-users:
        - my-new-backend:use
```

Principals in the `af-my-new-backend-users` Keycloak group will be granted
`my-new-backend:use`.

---

## Step 4 — Allow egress to the backend in NetworkPolicy (if needed)

If the backend pod is not already covered by an existing egress rule, add it to
the broker's NetworkPolicy. Edit
`charts/af-mcp-platform/templates/networkpolicy.yaml` or the relevant values key:

```yaml
values:
  networkPolicy:
    egressBackends:
      - namespace: af-mcp-backends
        podSelector:
          matchLabels:
            app.kubernetes.io/name: my-new-backend
```

If the backend is in the same namespace or already covered by a wildcard rule,
skip this step.

---

## Step 5 — Redeploy

```bash
flux reconcile helmrelease af-mcp-platform --namespace flux-system --with-source
```

Flux will render the new HelmRelease values, update the aggregator ConfigMap, and
roll the broker pods. The new backend's tools appear in `GET /v1/tools` once the
pods are healthy.

---

## Verification

```bash
# Check the broker sees the new backend
kubectl exec -n af-mcp deploy/af-mcp-broker -- \
  curl -s http://localhost:8080/v1/tools | jq '.[].backend' | sort -u

# Confirm the new backend's tools are listed
kubectl exec -n af-mcp deploy/af-mcp-broker -- \
  curl -s http://localhost:8080/v1/tools | jq '.[] | select(.backend=="my-new-backend")'
```
