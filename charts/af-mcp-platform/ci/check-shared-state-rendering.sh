#!/usr/bin/env bash
# Content assertions for the shared state key prefix (broker.sharedState.keyPrefix
# -> SHARED_STATE_KEY_PREFIX). `helm lint` only proves the values files render;
# this proves what lands in the output. Run from the repository root.
set -euo pipefail

chart=charts/af-mcp-platform
ci=$chart/ci
common=(--set image.broker.tag=sha-test --set image.portal.tag=sha-test)

render() {
  helm template "$@" "$chart" "${common[@]}" -f "$ci/shared-state-url-values.yaml"
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

# Default: derived from the release name, so two releases on one store differ.
rendered=$(render release-a)
expect_has "default, release-a" 'name: SHARED_STATE_KEY_PREFIX' "$rendered"
expect_has "default, release-a" 'value: "release-a:"' "$rendered"
rendered=$(render release-b)
expect_has "default, release-b" 'value: "release-b:"' "$rendered"

# Explicit value wins over the release name.
rendered=$(render release-a --set broker.sharedState.keyPrefix=custom:)
expect_has "explicit" 'value: "custom:"' "$rendered"
expect_lacks "explicit" 'value: "release-a:"' "$rendered"

# No shared store: nothing to namespace.
rendered=$(helm template release-a "$chart" "${common[@]}" -f "$ci/test-values.yaml" \
  --set broker.sharedState.url= --set broker.sharedState.existingSecret.name= \
  --set broker.sharedState.allowPerReplicaState=true)
expect_lacks "no store" 'SHARED_STATE_KEY_PREFIX' "$rendered"
