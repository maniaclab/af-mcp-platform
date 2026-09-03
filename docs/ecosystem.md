# Ecosystem

af-mcp-platform (this repo) is the broker + portal — the credential-brokering
core described in [Architecture](architecture.md). On its own it authenticates
callers and routes method calls (MCP "tools"); it doesn't mint grid
credentials or expose any compute itself. Those come from separate,
independently-deployed services that
plug into the broker's `identity_providers`/`services.yaml` extension points
(see [Authentication](auth.md) and [Adding a Service](adding-a-service.md)).

This page lists the real components that make up the UChicago ATLAS Analysis
Facility's deployment — the reference deployment, not a requirement. A
different facility can mix in its own backend MCP servers and credential
services behind the same broker; nothing here is hardcoded into this repo.

## The broker + portal

- **[af-mcp-platform](https://github.com/maniaclab/af-mcp-platform)** (this
  repo) — the credential broker and self-service portal described throughout
  these docs.

## Credential-minting services

Backends whose real credential isn't a plain OAuth token need a service that
mints it on the user's behalf, invoked via the broker's
[AF Broker Identity Token](auth.md#af-broker-identity-token-issue-162)
mechanism — see that section for the general native-backend pattern.

- **[condor-token-service](https://github.com/maniaclab/condor-token-service)**
  — mints HTCondor IDTOKENs for users who complete the broker's OIDC login,
  via the `condor-token` identity-provider type (see
  [Authentication](auth.md#condortokenprovider-htcondor-idtokens-issue-169)).
- **[krb5-token-service](https://github.com/maniaclab/krb5-token-service)**
  mints CERN Kerberos tickets (ccaches) for CERN-authenticated identities
  via the `krb5-token` identity-provider type (see
  [Authentication](auth.md#krbtokenprovider-cern-kerberos-tickets-issue-274)).
- **[voms-token-service](https://github.com/maniaclab/voms-token-service)** —
  mints x509/VOMS proxies for users who complete the broker's OIDC login,
  via an `x509` identity-provider entry with `serviceUrl` set (see
  [x509 deployment notes](x509-deployment-notes.md)).
- **[af-credentials](https://github.com/maniaclab/af-credentials)** — the
  library an x509-backed MCP server (like ami-mcp) uses to redeem a proxy
  from the broker at call time via `POST /v1/credentials/x509/redeem`,
  without the proxy PEM ever transiting the aggregator (see
  [Authentication](auth.md#identity-provider-types)).

## Backend MCP servers

Any MCP server can be a service — adding one is a `services.yaml` entry, no
broker code change (see [Adding a Service](adding-a-service.md)). These are
the ones registered in the reference deployment today:

- **[rucio-mcp](https://github.com/kratsg/rucio-mcp)** — ATLAS distributed
  data management: dataset/file/replica lookup, via the `oauth21-direct`
  identity-provider type (see
  [Rucio: Per-Site Setup](rucio-per-site-setup.md)).
- **[ami-mcp](https://github.com/kratsg/ami-mcp)** — ATLAS Metadata
  Interface: dataset provenance and physics metadata, via an x509/VOMS
  proxy redeemed through af-credentials above.
- **[golang-htcondor](https://github.com/bbockelm/golang-htcondor)** — the
  HTCondor MCP server (`condor-mcp` in the catalog), submitting and
  monitoring local cluster jobs; authenticates via condor-token-service
  above.
- **[af-jupyterlab-mcp](https://github.com/maniaclab/af-jupyterlab-mcp)** —
  starts, stops, and configures JupyterLab notebook servers on the facility,
  plus a proxy into each running notebook server's own MCP endpoint.
- **[af-filesystem-mcp](https://github.com/maniaclab/af-filesystem-mcp)** —
  browse and read files under a user's `/home/<user>` and `/data/<user>`.

## Deploying your own mix

None of the services above are required by af-mcp-platform itself — they're
what UChicago's ATLAS AF happens to run behind its broker. A different
facility or experiment deploys the same broker + portal chart and registers
whichever backend MCP servers and credential services fit its own compute
and storage systems; see [Adding a Service](adding-a-service.md) for the
config-only mechanism and [Authentication](auth.md) for the identity-provider
types available for wiring up a new credential-minting service.
