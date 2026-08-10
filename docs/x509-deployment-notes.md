# x509 backend deployment notes (issue #112)

What an operator (the flux_apps side) needs in place for an x509 backend —
ami-mcp is the first — to work end-to-end over `/mcp`. Code references:
`mcp/aggregator.py`'s x509 branch, `api/credentials.py`'s redeem endpoint,
and the [af-credentials](https://github.com/maniaclab/af-credentials) client
library (its own repository and PyPI package).

## The chain

```
user (portal unlock, passphrase)
  → broker mints VOMS proxy (X509Provider) and caches it
LLM client → mcp.af.uchicago.edu /mcp
  → aggregator mints AF Broker Identity Token (aud=ami) per call
  → ami-mcp verifies it against the broker JWKS (af-credentials)
  → ami-mcp redeems the proxy: POST /v1/credentials/x509/redeem
  → ami-mcp runs the AMI call with the proxy, deletes it immediately
```

## Broker side (this chart)

1. **Signing key** — `broker.identityToken.existingSigningKeySecret` must be
   set (same key the broker-issued / condor-token providers use). A keyless
   broker still boots but logs `x509_backends_without_signing_key` at
   startup, fails x509 tool calls with an actionable error, and answers 503
   on redeem.
2. **Backend entry** — `aggregator.backends` gets ami with
   `auth_type: x509`. That single flag drives portal minting (X509Provider
   registration), aggregator identity-JWT injection, and the redeem
   endpoint's audience gate. No `identity_providers` entry is needed.

   ```yaml
   aggregator:
     backends:
       - name: ami
         prefix: ami
         url: http://ami-mcp.<namespace>.svc.cluster.local:8000/mcp
         auth_type: x509
         required_capability: read_metadata   # or as policy dictates
   ```

3. **Proxy minting prerequisites** — unchanged from the existing X509Provider
   story: the minting path needs the users' home directories (the
   `af-user-homes` PVC, which does not exist on the AF yet) or, once it
   lands, the voms-token-service (see below). Until minting works, redeem
   returns the actionable 404 and ami-mcp surfaces "mint one at the AF
   portal".

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
  covered by `networkPolicy.broker.backendPorts`).

## voms-token-service (once adopted — replaces the ephemeral-Job mint path)

Scaffolded separately (repo shape mirrors condor-token-service). Flux entries
mirror `flux_apps/af/mcp-platform/`'s condor-token-service set:

- Deployment + Service from `charts/voms-token-service`; the **homes PVC
  mounts on this pod only** (read-only), never on the broker.
- Values: `brokerJwksUrl`, `brokerIssuer`, audience `voms-token-service`.
- NetworkPolicy: broker → voms-token-service egress only; the service needs
  no egress beyond VOMS servers.
- Broker settings gain the service URL when the X509Provider switches its
  mint path over (follow-up to this PR; proxies then persist in
  OpenBao/Vault instead of tmpfs, removing the broker's NFS needs entirely).

## Verification

1. `curl -s https://mcp.af.uchicago.edu/.well-known/jwks.json | jq .keys`
   — non-empty.
2. Portal → mint a proxy (unlock flow), then from a pod with a broker-issued
   test token: `curl -s -X POST -H "Authorization: Bearer $TOK" \
   https://<broker>/v1/credentials/x509/redeem | jq .dn,.remaining_seconds`.
3. `claude mcp add --transport http atlas-af https://mcp.af.uchicago.edu/mcp`
   and run `ami_execute` with a trivial `SearchQuery` as a real user; check
   the broker audit log for the paired `x509_proxy_release` record.
