# x509 backend deployment notes (issue #112)

What an operator (the flux_apps side) needs in place for an x509 backend —
ami-mcp is the first — to work end-to-end over `/mcp`. Code references:
`mcp/aggregator.py`'s x509 branch, `api/credentials.py`'s redeem endpoint,
`credentials/voms_service.py` + `credentials/x509_vault.py` (the
voms-token-service mint path), and the
[af-credentials](https://github.com/maniaclab/af-credentials) client
library (its own repository and PyPI package).

## The chain

```
user (portal LINK, one-time passphrase entry)
  → broker mints VOMS proxy via voms-token-service
  → broker stores passphrase + proxy in Vault/OpenBao (VaultX509Store)
LLM client → mcp.af.uchicago.edu /mcp
  → aggregator mints AF Broker Identity Token (aud=ami) per call
  → ami-mcp verifies it against the broker JWKS (af-credentials)
  → ami-mcp redeems the proxy: POST /v1/credentials/x509/redeem
      (expired? broker re-mints hands-free with the stored passphrase)
  → ami-mcp runs the AMI call with the proxy, deletes it immediately
```

With no `serviceUrl` on the x509 identity-provider entry, the pre-existing
chain applies instead: the portal unlock mints via an ephemeral k8s Job
that NFS-subPath-mounts the user's home, the proxy lives in the broker's
tmpfs, and nothing is persisted — every expiry needs a fresh portal unlock.

The global `broker.env.VOMS_TOKEN_SERVICE_URL` (and its
`_AUDIENCE`/`_VOMS`/`_VALID` companions) is not read at all — there is no
synthesized fallback for an entry-less `auth_type: x509` backend either,
so every such backend needs an explicit `identityProviders` entry (step 3
below), even a bare legacy one. See "Migrating off
`broker.env.VOMS_TOKEN_SERVICE_URL`" below if a deployment still sets it.

## Broker side (this chart)

1. **Signing key** — `broker.identityToken.existingSigningKeySecret` must be
   set (same key the broker-issued / condor-token providers use). Required
   at boot whenever an x509 entry has `serviceUrl` set; a keyless LEGACY
   entry (`serviceUrl` omitted) still boots but logs
   `x509_backends_without_signing_key` at startup, fails x509 tool calls
   with an actionable error, and answers 503 on redeem.
2. **Service entry** — `aggregator.services` gets ami with
   `auth_type: x509`. That flag drives aggregator identity-JWT injection
   and the redeem endpoint's audience gate.

   ```yaml
   aggregator:
     backends:
       - name: ami
         prefix: ami
         url: http://ami-mcp.<namespace>.svc.cluster.local:8000/mcp
         auth_type: x509
         required_permission: read_metadata   # or as policy dictates
   ```

3. **Identity-provider entry** — `broker.identityProviders` gets a
   `type: x509` entry targeting the backend. The broker refuses to start
   when an `auth_type: x509` backend and the x509 entries' `targets` drift
   in either direction, including the entry-less case — there is no
   synthesized fallback, so every x509 backend needs an explicit entry.

   ```yaml
   broker:
     identityProviders:
       - type: x509
         alias: x509
         displayName: "Grid certificate (x509)"
         enables: "VOMS proxy minting for x509-authenticated backends"
         targets: ["ami"]
         # voms-token-service mode; omit serviceUrl for the legacy Job path.
         serviceUrl: "http://voms-token-service.<namespace>.svc.cluster.local:8080"
         voms: "atlas"      # optional, default
         valid: "192:00"    # optional, default
   ```

   Multiple entries with different `serviceUrl`/`voms` values are supported
   (e.g. a second VO minting at its own voms-token-service).

4. **Proxy minting prerequisites** — either the voms-token-service path
   (preferred; see below) or the legacy Job path's requirement of the users'
   home directories on the broker (the `af-user-homes` PVC, which does not
   exist on the AF yet — the service path removes this need from the broker
   entirely). Until minting works, redeem returns the actionable 404 and
   ami-mcp surfaces "mint one at the AF portal".

## ami-mcp side (backend deployment)

Run ami-mcp ≥0.3.0 in broker mode:

```
ami-mcp serve --transport http --auth broker \
    --broker-url   https://mcp.af.uchicago.edu \
    --audience     ami \
    --host 0.0.0.0 --port 8000
```

(`--broker-jwks-url` defaults to `BROKER_URL/.well-known/jwks.json`,
`--broker-issuer` to `BROKER_URL` — override if the issuer URL the broker
stamps differs from the URL ami-mcp reaches it at in-cluster.)

- Needs `af-credentials[mcp]` installed (the `broker` extra of ami-mcp).
- Holds NO credential of its own: no `X509_USER_PROXY`, no homes mount.
  `X509_CERT_DIR` is still required for pyAMI's TLS verification of
  atlas-ami.cern.ch (ship the grid CA bundle, e.g. conda-forge
  `ca-policy-lcg`).
- NetworkPolicy: ami-mcp needs egress to the broker (redeem + JWKS) and to
  atlas-ami.cern.ch:443; the broker needs egress to ami-mcp:8000 (already
  covered by `networkPolicy.broker.servicePorts`).

## voms-token-service mode (replaces the ephemeral-Job mint path)

The service lives in its own repository
([maniaclab/voms-token-service](https://github.com/maniaclab/voms-token-service);
repo shape mirrors condor-token-service). Flux entries mirror
`flux_apps/af/mcp-platform/`'s condor-token-service set:

- Deployment + Service from `charts/voms-token-service`; the **homes PVC
  mounts on this pod only** (read-only), never on the broker.
- Service values: `brokerJwksUrl`, `brokerIssuer`, audience
  `voms-token-service`, `HOME_ROOT` (the `.globus` parent directory root on
  the mounted PVC — configurable, default `/home`).
- NetworkPolicy: broker → voms-token-service egress only; the service needs
  no egress beyond VOMS servers (plus the broker JWKS endpoint).

### Broker settings (per x509 identityProviders entry / chart values)

| Setting | Meaning |
| --- | --- |
| entry `serviceUrl` | Base URL of the service (no path). **Omitted = legacy Job path**, exactly the pre-service behavior. |
| entry `audience` | `aud` minted into the mint call's AF Broker Identity Token; must match the service's `EXPECTED_AUDIENCE` (default `voms-token-service`). |
| entry `voms` / `valid` | `voms`/`valid` forwarded on every mint (defaults `atlas` / `192:00`). |
| `X509_KV_PATH_PREFIX` | KV-v2 path prefix for the per-subject records (default `mcp/x509`), shared by every service-mode entry — one link record per user, not per service. |
| `VAULT_ADDR`, `VAULT_AUTH_MOUNT`, `VAULT_AUTH_ROLE`, `VAULT_KV_MOUNT`, `VAULT_SA_TOKEN_PATH` | The same shared Vault connection the other Vault-backed stores use (chart: `broker.oauth21.tokenStore.vault`). **Required** when any entry has a `serviceUrl` (startup validation refuses a half-configured broker). |
| `BROKER_SIGNING_KEY_FILE` | **Required** whenever an x509 entry has `serviceUrl` set — the aggregator's identity JWTs, the redeem endpoint, and the mint call are all authenticated by broker-signed identity tokens (fail-closed at boot). A keyless legacy entry (`serviceUrl` omitted) only warns. |

#### Migrating off `broker.env.VOMS_TOKEN_SERVICE_URL`

The global env vars (`VOMS_TOKEN_SERVICE_URL`, `VOMS_TOKEN_SERVICE_AUDIENCE`,
`VOMS_TOKEN_SERVICE_VOMS`, `VOMS_TOKEN_SERVICE_VALID`, previously set via
`broker.env` in the HelmRelease) are no longer read by the broker at all —
declare the per-entry fields above instead. Replace

```yaml
broker:
  env:
    VOMS_TOKEN_SERVICE_URL: "http://voms-token-service.<namespace>.svc.cluster.local:8080"
```

with the `identityProviders` entry shown in "Broker side" step 3 above, then
remove the env var from `broker.env`. There is no transition period: an
`auth_type: x509` backend with no explicit `identityProviders` entry
refuses to boot.

### Vault paths + policy

One KV-v2 record per subject at
`{VAULT_KV_MOUNT}/data/{X509_KV_PATH_PREFIX}/{subject}/x509` holding the
Globus passphrase, the POSIX identity captured at link time, and the current
proxy PEM with its expiry. The broker's Vault policy needs, on
`{X509_KV_PATH_PREFIX}/*`: `create`+`update` on `data/` (CAS writes),
`read` on `data/`, and `delete` on `metadata/` (unlink destroys all
versions). This prefix is deliberately distinct from
`VAULT_KV_PATH_PREFIX`/`TOKEN_REGISTRY_KV_PATH_PREFIX`/
`PRINCIPAL_CACHE_KV_PATH_PREFIX` so the four stores never collide, and it
holds the platform's most sensitive material — scope the policy to exactly
this prefix, nothing broader.

### The link / re-link UX

- **Link (once)**: the user enters their Globus passphrase at the portal
  (`POST /v1/x509/proxy`, the pre-existing unlock endpoint). The broker
  mints via the service and stores passphrase + proxy in Vault. A bad
  passphrase is a 400 (and burns the unlock rate-limit budget, as before);
  a service outage is a 502 (and does not).
- **Hands-free renewal**: any consumer hitting an expired stored proxy —
  `issue()` on the `/v1` surface, or the redeem endpoint mid-tool-call —
  triggers a re-mint with the stored passphrase; the user does nothing.
- **Re-link**: if a hands-free re-mint fails on a bad passphrase (the user
  changed their Globus password), the record is deleted (unlink) and the
  user is prompted — redeem answers 404 "re-link at the AF portal",
  `is_linked()` flips to false. Entering the new passphrase at the portal
  re-links.
- **Revoke** (`DELETE /v1/x509/proxy`): clears the stored proxy but keeps
  the link — the next issue renews hands-free. Unlinking is only ever the
  bad-passphrase path above (or a future portal unlink action).
- **Portal visibility**: each x509 `identity_providers` entry is an
  ordinary row on `GET /v1/identities` (its `alias` matching the
  `credential_provider` alias `/v1/catalog` reports for its targets):
  `linked` from `X509Provider.is_linked()` (Vault in service mode, the
  `~/.globus` heuristic in legacy mode), `link_mechanism: "passphrase"`
  (no `link_url` — linking is the in-portal passphrase form, not a
  redirect), and `proxy_expires_at` from the cached proxy metadata. The
  Identities page renders it as its own card whose Link/Re-link action
  POSTs to `/v1/x509/proxy`, surfacing the 400/429/502 taxonomy above
  inline.

### What changed vs the tmpfs/Job era

| | tmpfs/Job (legacy, no serviceUrl) | voms-token-service + Vault |
| --- | --- | --- |
| Mint | ephemeral k8s Job, NFS-subPath mount of the user's home **on the broker's cluster config** | HTTP call to voms-token-service (only IT mounts homes) |
| Proxy storage | broker tmpfs (`PROXY_DIR`), lost on restart | Vault KV-v2, shared across replicas and restarts |
| Passphrase | never persisted; re-entered at every expiry | persisted in Vault (the issue #112 custodianship decision) for hands-free renewal |
| Expiry | proxy silently unusable until the user unlocks again | renewed hands-free; user only re-enters on a changed Globus password |
| Credential kind | `x509_proxy_ref` (`proxy_path` on the broker filesystem) | `x509_proxy_redeem` (no local file; backends redeem the PEM) |
| Broker POSIX/NFS needs | homes PVC + per-uid Job plumbing | none (POSIX identity is captured at link time and asserted to the service) |

## Verification

1. `curl -s https://mcp.af.uchicago.edu/.well-known/jwks.json | jq .keys`
   — non-empty.
2. Portal → mint a proxy (unlock flow), then from a pod with a broker-issued
   test token: `curl -s -X POST -H "Authorization: Bearer $TOK" \
   https://<broker>/v1/credentials/x509/redeem | jq .dn,.remaining_seconds`.
3. `claude mcp add --transport http atlas-af https://mcp.af.uchicago.edu/mcp`
   and run `ami_execute` with a trivial `SearchQuery` as a real user; check
   the broker audit log for the paired `x509_proxy_release` record.
