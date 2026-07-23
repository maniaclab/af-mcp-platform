# Authentication & Credential Chain

## Full Auth Chain

```
ATLAS AF User
    │
    │  (1) Login via AF portal / device flow
    ▼
AF Keycloak  ──────────────────────────────────────────────────────────────
    │  issues AF access token (JWT, audience: mcp-gateway)
    ▼
oauth2-proxy  (sidecar in front of the broker ingress)
    │  validates token signature + expiry + audience
    │  forwards: Authorization: Bearer <af-token>
    ▼
AF Credential Broker  (Identity subsystem)
    │  re-validates JWT (defence-in-depth)
    │  resolves uid/gid from the token's posix claim
    │  resolves capabilities from the token's groups claim via policy.yaml
    ▼
Credential subsystem
    │
    ├── Path A: ATLAS IAM token (for Rucio, PanDA, AMI)
    │       GET /realms/connect/broker/atlas-oidc/token
    │       (Keycloak's stored brokered token for the principal's linked
    │        atlas-auth.cern.ch identity — this is the ONLY way to obtain
    │        a token that atlas-auth.cern.ch will accept)
    │
    ├── Path B: AF-internal token exchange (for AF-local services only)
    │       POST /realms/<realm>/protocol/openid-connect/token
    │       grant_type=urn:ietf:params:oauth:grant-type:token-exchange
    │       subject_token=<af-token>
    │       requested_token_type=urn:ietf:params:oauth:token-type:access_token
    │       audience=<af-internal-service>
    │       *** THIS TOKEN IS NOT ACCEPTED BY atlas-auth.cern.ch ***
    │
    └── Path C: x509/VOMS proxy (for grid jobs, SRM, FTS)
            Ephemeral k8s Job mounts ~/.globus/{usercert,userkey}.pem
            via NFS subPath, runs voms-proxy-init, returns proxy
            (see spikes/nfs-subpath/ for validation)
    │
    ▼
Backend MCP server  (receives brokered credential in the Authorization header
                     or as a file-mount via a shared emptyDir)
```

---

## Critical Note: Keycloak Token Exchange Limitations

**Keycloak Standard Token Exchange (V2) is internal-to-AF only.**

When the broker calls Keycloak's token exchange endpoint on behalf of a principal,
the resulting token has:

- Issuer: `https://keycloak-prod.tempest.uchicago.edu/realms/connect`
- Audience: whatever `audience` was requested (an AF-internal service)

`atlas-auth.cern.ch` (the CERN IAM instance that issues tokens for Rucio, PanDA,
and AMI) **will reject** this token. It only trusts tokens issued by itself or
by federation partners it has explicitly configured.

**The correct path for ATLAS service credentials** is the stored brokered token
that Keycloak holds after the principal has linked their CERN account:

```
GET https://keycloak-prod.tempest.uchicago.edu/realms/connect/broker/atlas-oidc/token
Authorization: Bearer <af-token>
```

(`atlas-oidc` is the IdP alias in the connect realm; configurable via
`ATLAS_IAM_BROKER_ALIAS`.)

This returns the ATLAS IAM access token that Keycloak obtained during the
account-linking flow. That token:

- Is issued by `atlas-auth.cern.ch`
- Carries the principal's CERN identity and VO attributes
- Is accepted by Rucio, PanDA, and AMI

The broker always uses this path when the target backend requires an ATLAS IAM
credential. Operators must ensure that:

1. AF Keycloak is configured as an identity provider for `atlas-auth.cern.ch`
   (or vice versa — the federation direction matters).
2. Users have completed the account-linking step in the AF portal before their
   first tool call that requires an ATLAS credential.
3. The broker's service account has permission to call the broker token endpoint
   (Keycloak fine-grained authorization, `view-token` scope on the `atlas-oidc`
   identity provider).

---

## Token Lifetime and Refresh

| Credential type | Typical lifetime | Refresh strategy |
|---|---|---|
| AF access token | 5 minutes | oauth2-proxy handles refresh transparently |
| ATLAS IAM token (brokered) | 1 hour | Broker re-fetches from Keycloak on cache miss |
| x509 VOMS proxy | 12–96 hours (configurable) | Re-mint Job triggered when cache entry expires |

The `CredentialCache` stores each credential with its `expires_at` timestamp.
A background janitor coroutine sweeps the cache every 60 seconds and evicts
expired entries, triggering a fresh mint on the next request.

---

## Group-to-Capability Mapping Example

From the shipped `policy.yaml` (mounted from the chart's policy ConfigMap):

```yaml
group_capabilities:
  atlas: [read_data, read_metadata, read_monitoring, read_gitlab,
          submit_jobs, manage_jobs, launch_compute, manage_jupyter,
          manage_gitlab]
  escape: [read_data, read_metadata]
  # Any authenticated user (no group membership required)
  __authenticated__: [read_metadata, read_monitoring]

target_capabilities:
  rucio: read_data
  ami: read_metadata
  panda: submit_jobs
  docs: __none__     # open to any authenticated user
```

Keycloak group membership is resolved once per request from the validated
token's `groups` claim. There is no group-membership cache in the broker —
Keycloak is the authoritative source.

---

## Auth-edge decision

#26 found the shared oauth2-proxy (`provider = "keycloak-oidc"`, v7.6.0)
validates a Bearer's `aud` claim against its own `client_id`, not the
broker's audience — so mcpHost's ForwardAuth gate 302'd every Bearer
request, including Claude Desktop's, instead of letting it reach the
broker's own JWT validator:

```
$ curl -sS -o /dev/null -w "HTTP %{http_code}\nLocation: %{redirect_url}\n" https://mcp.af.uchicago.edu/mcp/
HTTP 302
Location: https://oauth2-proxy.af.uchicago.edu/oauth2/sign_in?rd=%2Fmcp%2F
```

Phase A (`ingress-mcp.yaml` / `ingress-portal.yaml` split) removes the
oauth2-proxy annotations from mcpHost so the broker validates Bearers
itself. portalHost is unaffected and still 401s on `/v1/*` until the portal
becomes its own OAuth client — see #42 for the full follow-through.
