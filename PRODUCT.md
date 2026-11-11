# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Two audiences, both first-class:

- **Physics users** — each deployment's own signed-in users, doing self-service work
  on their own account.
- **Facility operators** — members of the deployment's admin Keycloak group
  (`broker.adminGroup`, see `docs/admin.md`), who additionally get the Admin page:
  usage across users, maintenance mode, annotation mismatches, tool-mapping drift, and
  HTCondor credmon sync. Operators still manage `policy.yaml` / `services.yaml`
  outside the portal, via config PRs to the repo (see `docs/adding-a-service.md`).

The reference deployment is UChicago's ATLAS Analysis Facility (AF): ~800 physics users,
who with its operators are the audience for its portal (`mcp-portal.af.uchicago.edu`) and its broker
(`mcp.af.uchicago.edu`). Other facilities deploying this platform have their own user
population and hostnames for the same two surfaces.

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

A credential-brokered MCP (Model Context Protocol) gateway: one endpoint per
deployment (the reference deployment's is `mcp.af.uchicago.edu`) that authenticates a
caller against that facility's Keycloak, brokers per-user credentials to downstream
ATLAS systems, and aggregates every registered backend MCP server behind that single
URL. Success means a facility's user's MCP client (Claude Desktop, Gemini, etc.) can
call Rucio/AMI/PanDA/etc. tools directly, with the broker handling auth, authorization,
and credential minting transparently and auditably — the user never sees or holds a
raw x509/IAM credential.

## Positioning

The broker is the strategic platform boundary a neighboring point-to-point MCP
integration could not truthfully claim: LLM clients never hold raw credentials (x509
proxies, ATLAS IAM tokens) — the broker authenticates the caller once, mints
short-lived per-user credentials behind the scenes, and every tool invocation passes
through one authorization + audit layer regardless of which backend it eventually
reaches. Adding a new service is config-only (`services.yaml`), no code change, so the
platform can aggregate an arbitrary and growing number of ATLAS MCP servers behind one
URL without multiplying the number of places a client must trust with credentials.

## Operating Context

- Two hosts per deployment: one for MCP-over-HTTP (any client, broker validates its own
  Bearer directly) and one for the portal SPA (its own OIDC login, enforced client-side —
  `/v1` and `/mcp` carry no gate of their own on either host). The reference
  deployment's are `mcp.af.uchicago.edu` and `mcp-portal.af.uchicago.edu`.
- The portal has one public page and seven signed-in pages:
    - Public landing page (`/`): says what the platform is and gets a facility user
      signed in. Sign-in is its primary action; its gateway diagram explains the
      credential-brokering request flow.
    - Overview (`/overview`): dashboard + MCP endpoint connection snippets.
    - Services (`/catalog`): backends/tools reachable by the signed-in account.
    - Identities (`/identities`): link external CERN/ATLAS accounts, plus the x509
      grid-certificate card (VOMS proxy linking, custody consent, preflight checklist,
      proxy status), krb5, and ServiceX credentials.
    - Tokens (`/tokens`): mint/revoke static bearer tokens for OAuth-discovery-less
      clients like Claude Desktop.
    - Usage (`/usage`): the signed-in user's own calls, errors, tokens, and estimated
      cost per service over 7/30/90 days.
    - Entitlements (`/entitlements`): the permission × group matrix, with each permission's kind and description taken from the broker's `GET /v1/entitlements` catalog.
    - Admin (`/admin`): operators only (see **Users**).
- Users first reach the portal for setup (link an identity, mint a token), and it is
  becoming something they check regularly (service status, proxy state, usage). This is
  the maintainer's judgment, not a measured pattern (see **Evidence on Hand**). The
  actual ATLAS computing work (dataset queries, job submission) still happens inside
  their MCP client, not in the portal.
- Backend MCP servers in the aggregator today: rucio-mcp (ATLAS + ESCAPE),
  ami-mcp, condor-mcp, jupyterlab-mcp, filesystem-mcp; planned: panda-mcp.

## Capabilities and Constraints

- Identity: broker accepts a Keycloak JWT (`Authorization: Bearer`) or a
  broker-issued PAT (`mcp_pat_…`, `/mcp` only). Groups/POSIX uid/gid come from a
  directory-backed `PrincipalCache`, never from token claims.
- Authorization: declarative `policy.yaml` maps groups to permissions; each
  service's required permission is defined once, in `services.yaml` (the
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
- Adding a service is config-only (`services.yaml`) — no broker code change required.
- Accessibility: `eslint-plugin-vuejs-accessibility` already lints every `.vue`
  template in CI (see commit `7a49dfa`).

## Brand Commitments

- The portal's working pages follow the conventions of established infrastructure
  consoles, played straight. The reference bar is GitHub's settings pages, the
  Tailscale and Cloudflare admin consoles, and Grafana.
- Ruled out as outcomes: a sci-fi terminal look (dark, mono everywhere, glowing
  accents), a generic component-library dashboard, a heavy enterprise portal, and
  consumer-SaaS marketing flourishes inside the app.
- Kept from the earlier look: both light and dark themes, the particle-track canvas
  on the Overview page, and the gateway diagram animation on the public landing page.
- The default theme is neutral and monochrome: the accent is ink (black in light mode,
  white in dark). A facility may opt into its own accent colour; the portal never
  assigns a deployment an identity it has not chosen. The accent is used only for the
  primary action and the current-location marker.
- Status and alert colours (success, warning, danger, information) are fixed across
  deployments and are never the accent, so a facility whose colour is red or yellow
  cannot make an ordinary notice look like an error or a warning.
- Type is one family: IBM Plex Sans for headings and text, with IBM Plex Mono
  reserved for values a user copies or compares literally. Number columns use its
  tabular numerals so they align.
- Icons are Lucide, rendered as inline SVG from its published packages.
- The worked reference for all of the above is `docs/design-language/index.html`.

## Evidence on Hand

None yet. No collected user feedback, support-channel data, or usage metrics exist
from the reference deployment's ~800 AF users, or from any other deployment. Future
design work must not invent testimonials, satisfaction claims, or usage numbers to
fill this gap.

## Product Principles

- Credentials are the broker's job, never the client's: no UI flow should ask a user
  to paste, view, or manage a raw x509/IAM credential — only broker-issued tokens and
  proxy status.
- Config-only extensibility: the platform's growth path is adding backends via
  `services.yaml`, not code changes — portal surfaces (like the catalog) should
  reflect that registry-driven model rather than hardcoding backend knowledge.
- Two audiences, one portal: physics users act only on their own account; operators
  see the platform's state across users on the Admin page. Neither is an afterthought
  of the other.
- A regular check, not only a setup wizard: after first setup, the portal's job is to
  show the state of a user's access (services, identities, proxy, tokens, usage) and
  what to do when something is wrong. The ATLAS computing work itself stays in the
  user's MCP client, not in more portal screens.

## Accessibility & Inclusion

Target: WCAG 2.1 AA. `eslint-plugin-vuejs-accessibility` is already wired into the
portal's lint pipeline as a first enforcement layer; treat AA as the real bar for
audits and new UI, not just what the linter catches.
