#!/usr/bin/env bash
# Content assertions for the Vault connection env (VAULT_*), the per-store KV
# path prefixes, and the oauth21-direct revocation endpoint. `helm lint` only
# proves these values files render; this proves what lands in the output. Run
# from the repository root.
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

# Per-store KV prefixes: broker defaults unless overridden per release.
rendered=$(render -f "$ci/vault-values.yaml")
for pair in \
  X509_KV_PATH_PREFIX:mcp/x509 \
  KRB5_KV_PATH_PREFIX:mcp/krb5 \
  SERVICEX_KV_PATH_PREFIX:mcp/servicex \
  CREDMON_STATE_KV_PATH_PREFIX:mcp/credmon; do
  expect_has "default ${pair%%:*}" "name: ${pair%%:*}" "$rendered"
  expect_has "default ${pair%%:*}" "value: \"${pair#*:}\"" "$rendered"
done
rendered=$(render -f "$ci/vault-values.yaml" \
  --set broker.vault.x509KvPathPrefix=mcp/b/x509 \
  --set broker.vault.krb5KvPathPrefix=mcp/b/krb5 \
  --set broker.vault.servicexKvPathPrefix=mcp/b/servicex \
  --set broker.vault.credmonKvPathPrefix=mcp/b/credmon)
for pair in \
  X509_KV_PATH_PREFIX:mcp/b/x509 \
  KRB5_KV_PATH_PREFIX:mcp/b/krb5 \
  SERVICEX_KV_PATH_PREFIX:mcp/b/servicex \
  CREDMON_STATE_KV_PATH_PREFIX:mcp/b/credmon; do
  expect_has "override ${pair%%:*}" "value: \"${pair#*:}\"" "$rendered"
done

# oauth21-direct revocation endpoint reaches IDENTITY_PROVIDERS.
rendered=$(render -f "$ci/vault-values.yaml")
expect_has "revocation_endpoint" '\"revocation_endpoint\":\"https://rucio-mcp.example.com/revoke\"' "$rendered"
