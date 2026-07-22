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

## Programmatic client bootstrap

The chain above ("Full Auth Chain") describes the interactive path:
oauth2-proxy handles browser-based OIDC login transparently, and a signed-in
user never fetches, pastes, or configures a raw bearer token by hand. That
story is unchanged and remains the default for anyone opening
`mcp.af.uchicago.edu` in a browser-capable client.

It does not cover MCP clients that speak MCP-over-HTTP but can't yet perform
OAuth discovery — Claude Desktop today. Those clients have no browser session
to inherit and no way to run the OIDC dance themselves, so they need a static
Bearer token to put directly in their config's `Authorization` header. The
portal's `mcp-portal.af.uchicago.edu/tokens` page exists for exactly this:

1. **Mint** — `POST /v1/tokens` performs a Keycloak RFC 8693 token exchange,
   self-audience (`aud=mcp-gateway`). This is "Path B" above (AF-internal
   token exchange), not Path A — the token only ever needs to satisfy this
   broker's own `identity.keycloak_dependency`, so the "atlas-auth.cern.ch
   rejects this token" caveat for Path B does not apply. The plain token
   value is shown exactly once by the portal.
2. **List** — `GET /v1/tokens` shows tokens minted through this endpoint
   (`source: "manual"`). Keycloak's admin REST API exposes user sessions and
   IdP consents, not per-token metadata for RFC 8693 token-exchange output,
   so tokens issued via the interactive oauth2-proxy flow or a future MCP
   OAuth flow are not enumerable here — a real gap, documented rather than
   silently omitted.
3. **Revoke** — `DELETE /v1/tokens/{jti}` removes the row from the list and
   best-effort-calls Keycloak's RFC 7009 revoke endpoint. Because this
   broker validates bearer tokens via local JWT signature verification
   against the JWKS (not Keycloak introspection), a successful upstream
   revoke does not by itself force the broker to reject the token before its
   natural expiry — true early revocation would require wiring jti-denylist
   enforcement into `identity.keycloak_dependency`, tracked as follow-up
   work.

This is a stopgap. Once MCP OAuth discovery lands and Claude Desktop (or
whichever client) can drive the flow itself, the manual `/tokens` page
becomes unnecessary for that client — the interactive and MCP-OAuth paths
both bypass it already. Until then, both stories coexist: sign in with a
browser and you never see a token; connect a client that can't do OAuth
discovery yet and you mint one here.
