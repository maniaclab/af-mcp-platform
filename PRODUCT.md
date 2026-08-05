# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

The ~800 physics users of the UChicago ATLAS Analysis Facility (AF). They are the sole
audience for the portal (`mcp-portal.af.uchicago.edu`) as well as the broker itself
(`mcp.af.uchicago.edu`) — self-service only. There is no separate operator/admin role
inside the portal UI; operators manage `policy.yaml` / `backends.yaml` outside the portal,
via config PRs to the repo (see `docs/adding-a-backend.md`), not through any UI surface.

Their job when using the portal: link external identities (CERN/ATLAS IAM via OIDC), mint
an on-demand x509/VOMS proxy for grid access, generate/revoke bearer tokens for MCP clients
that don't yet support OAuth discovery (e.g. Claude Desktop), and see which MCP backends
their account can currently reach.

Their job when using the platform overall (outside the portal, via any MCP client): drive
ATLAS computing tools — dataset lookup (Rucio), metadata queries (AMI), job submission and
monitoring (PanDA), local cluster jobs (HTCondor), GitLab operations, Jupyter kernel control
— from within their AI assistant, without ever handling the underlying grid credentials
themselves.

## Product Purpose

A credential-brokered MCP (Model Context Protocol) gateway: one endpoint
(`mcp.af.uchicago.edu`) that authenticates a caller against AF Keycloak, brokers
per-user credentials to downstream ATLAS systems, and aggregates every registered
backend MCP server behind that single URL. Success means an AF user's MCP client
(Claude Desktop, Gemini, etc.) can call Rucio/AMI/PanDA/etc. tools directly, with the
broker handling auth, authorization, and credential minting transparently and
auditably — the user never sees or holds a raw x509/IAM credential.

## Positioning

The broker is the strategic platform boundary a neighboring point-to-point MCP
integration could not truthfully claim: LLM clients never hold raw credentials (x509
proxies, ATLAS IAM tokens) — the broker authenticates the caller once, mints
short-lived per-user credentials behind the scenes, and every tool invocation passes
through one authorization + audit layer regardless of which backend it eventually
reaches. Adding a new backend is config-only (`backends.yaml`), no code change, so the
platform can aggregate an arbitrary and growing number of ATLAS MCP servers behind one
URL without multiplying the number of places a client must trust with credentials.

## Operating Context

- Two hosts: `mcp.af.uchicago.edu` (MCP-over-HTTP for any client, broker validates its
  own Bearer, no oauth2-proxy) and `mcp-portal.af.uchicago.edu` (the portal SPA, its
  own OIDC login; oauth2-proxy fronts only its HTML — `/v1` and `/mcp` bypass it on
  both hosts).
- The portal has five real screens today: Overview (`/`, dashboard + MCP endpoint
  connection snippets), MCP Servers catalog (`/catalog`, backends/tools reachable by
  the signed-in account), Identities (`/identities`, link external CERN/ATLAS
  accounts), AMI Proxy (`/status`, on-demand x509/VOMS proxy generation and status),
  and Tokens (`/tokens`, mint/revoke static bearer tokens for OAuth-discovery-less
  clients like Claude Desktop).
- Users reach the portal from a browser to do setup/bootstrapping tasks (link an
  identity, mint a token, check proxy status); the actual day-to-day work (dataset
  queries, job submission) happens inside their MCP client, not in the portal.
- Backend MCP servers in the aggregator today or planned: rucio-mcp, ami-mcp,
  openmagic, panda-mcp, condor-mcp, gitlab-mcp, jupyter-control.

## Capabilities and Constraints

- Identity: broker accepts a Keycloak JWT (`Authorization: Bearer`) or a
  broker-issued PAT (`mcp_pat_…`, `/mcp` only). Groups/POSIX uid/gid come from a
  directory-backed `PrincipalCache`, never from token claims.
- Authorization: declarative `policy.yaml` maps groups to capabilities; each
  backend's required capability is defined once, in `backends.yaml` (the
  authoritative registry).
- Credentials: provider classes behind `CredentialProvider` (oidc, oauth21, x509,
  service); minted credentials are cached in-process by `(subject, target)` with
  expiry sweeping. x509 proxies are minted via ephemeral k8s Jobs that NFS-subPath-mount
  the user's `~/.globus`; the passphrase is used once, never stored.
- Hard external constraint: Keycloak Standard Token Exchange (V2) tokens are accepted
  only by AF-internal services — `atlas-auth.cern.ch` rejects them. Any credential for
  external ATLAS services must instead use Keycloak's stored brokered token
  (`GET /realms/<realm>/broker/atlas-oidc/token`), which requires the user to have
  linked their CERN account first (the portal's Identities page is how they do that).
- Adding a backend is config-only (`backends.yaml`) — no broker code change required.
- Accessibility: `eslint-plugin-vuejs-accessibility` already lints every `.vue`
  template in CI (see commit `7a49dfa`).

## Evidence on Hand

None yet. No collected user feedback, support-channel data, or usage metrics exist
from the ~800 AF users. Future design work must not invent testimonials, satisfaction
claims, or usage numbers to fill this gap.

## Product Principles

- Credentials are the broker's job, never the client's: no UI flow should ask a user
  to paste, view, or manage a raw x509/IAM credential — only broker-issued tokens and
  proxy status.
- Config-only extensibility: the platform's growth path is adding backends via
  `backends.yaml`, not code changes — portal surfaces (like the catalog) should
  reflect that registry-driven model rather than hardcoding backend knowledge.
- Self-service, not admin tooling: every portal screen serves the signed-in user's own
  account; there is no multi-user management surface to design for.
- Bootstrapping, not daily-driver: the portal exists to set up and check status
  (identities, tokens, proxy) — the actual ATLAS computing work happens in the user's
  MCP client, not in more portal screens.

## Accessibility & Inclusion

Target: WCAG 2.1 AA. `eslint-plugin-vuejs-accessibility` is already wired into the
portal's lint pipeline as a first enforcement layer; treat AA as the real bar for
audits and new UI, not just what the linter catches.
