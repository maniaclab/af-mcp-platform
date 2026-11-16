#!/usr/bin/env bash
# Content assertions for the Vault connection env (VAULT_*), the KV root, and
# the oauth21-direct revocation endpoint. `helm lint` only proves these values
# files render; this proves what lands in the output. Run from the repository
# root.
set -euo pipefail

chart=charts/af-mcp-platform
ci=$chart/ci
common=(--set image.broker.tag=sha-test --set image.portal.tag=sha-test)

render() {
  helm template af-mcp-platform "$chart" "${common[@]}" "$@"
}

# expect_has <description> <needle> <rendered>
expect_has() {
  grep -qF -- "$2" <<<"$3" || {
    echo "FAIL ($1): missing '$2'" >&2
    exit 1
  }
}

# expect_lacks <description> <needle> <rendered>
expect_lacks() {
  if grep -qF -- "$2" <<<"$3"; then
    echo "FAIL ($1): unexpected '$2'" >&2
    exit 1
  fi
}

# Every Vault-capable backend alone must render the Vault connection env;
# config.py's _validate_vault_config refuses to boot without it.
for backend in \
  broker.oauth21.tokenStore.backend \
  broker.tokenRegistry.backend \
  broker.principalCache.backend \
  broker.maintenanceMode.backend; do
  rendered=$(render -f "$ci/vault-values.yaml" \
    --set broker.maintenanceMode.backend=in-memory --set "$backend=vault")
  expect_has "$backend=vault" 'name: VAULT_ADDR' "$rendered"
  expect_has "$backend=vault" 'name: VAULT_AUTH_ROLE' "$rendered"
done

# No Vault consumer: no Vault env at all.
rendered=$(render -f "$ci/vault-values.yaml" --set broker.maintenanceMode.backend=in-memory)
expect_lacks "no vault consumer" 'name: VAULT_ADDR' "$rendered"

# The KV root is the only prefix setting; the broker derives every store's
# prefix from it. A per-release root reaches the broker env, and the
# per-store prefix env vars are never rendered.
rendered=$(render -f "$ci/vault-values.yaml")
expect_has "kvRoot" 'name: VAULT_KV_ROOT' "$rendered"
expect_has "kvRoot" 'value: "mcp"' "$rendered"
expect_lacks "per-store prefix" 'KV_PATH_PREFIX' "$rendered"
rendered=$(render -f "$ci/vault-values.yaml" --set broker.vault.kvRoot=example-ops)
expect_has "kvRoot override" 'value: "example-ops"' "$rendered"

# A Vault consumer without a root fails the render, naming the value.
if err=$(render -f "$ci/vault-values.yaml" --set broker.vault.kvRoot= 2>&1); then
  echo "FAIL (missing kvRoot): render succeeded" >&2
  exit 1
fi
expect_has "missing kvRoot" 'broker.vault.kvRoot is required' "$err"

# No Vault consumer: no root needed and none rendered.
rendered=$(render -f "$ci/vault-values.yaml" \
  --set broker.maintenanceMode.backend=in-memory --set broker.vault.kvRoot=)
expect_lacks "no vault consumer" 'VAULT_KV_ROOT' "$rendered"

# oauth21-direct revocation endpoint reaches IDENTITY_PROVIDERS.
rendered=$(render -f "$ci/vault-values.yaml")
expect_has "revocation_endpoint" '\"revocation_endpoint\":\"https://rucio-mcp.example.com/revoke\"' "$rendered"
