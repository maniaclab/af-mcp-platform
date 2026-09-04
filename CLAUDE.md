# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A credential-brokered MCP (Model Context Protocol) gateway for an analysis facility. LLM clients hit one broker endpoint; the broker authenticates them against the facility's Keycloak, checks authorization, brokers per-user credentials (IAM tokens, x509/VOMS proxies), and forwards tool calls to backend MCP servers (rucio-mcp, panda-mcp, ami-mcp, ...). LLM clients never hold raw credentials. The reference deployment is UChicago's ATLAS Analysis Facility (`mcp.af.uchicago.edu`); other facilities deploy the same chart with their own Keycloak realm, policy, and backend registry.

## Commands

Everything Python runs through [pixi](https://pixi.sh); dependencies live in `pixi.toml` (the broker's `pyproject.toml` intentionally declares no dependencies).

```bash
pixi run broker              # run broker locally with reload → http://localhost:8080/docs
pixi run test                # broker unit tests (pytest broker/ -v)
pixi run test-spikes         # spike validation tests (pytest spikes/ -v)
pixi run lint                # ruff check + format --check on broker/
pixi run fmt                 # ruff format + autofix
pixi run typecheck           # mypy broker/src
pixi run -e dev lint-all     # everything the CI lint job runs (ruff + mypy + pre-commit)
pixi run -e dev pytest broker/ -k <name> -v   # single test
```

Portal (Astro + Vue + Tailwind):

```bash
pixi run -e portal dev        # dev server on :4321, proxies /v1/* to broker
pixi run -e portal build      # what CI checks
```

The two-terminal broker + portal workflow (and the
`BROKER_DEV_INSECURE_PRINCIPAL` local-dev auth bypass) is documented in
`docs/local-development.md`.

Helm chart: `helm lint charts/af-mcp-platform` (CI runs chart-testing in `chart-lint.yaml`).

## Architecture

Monorepo layout:

- `broker/` — Python 3.12 FastAPI app (`af_mcp_broker`), the core service
- `portal/` — Astro/Vue user-facing portal (catalog, identities, proxy status)
- `charts/af-mcp-platform/` — Helm chart deploying broker + portal (Flux CD in production)
- `spikes/` — validation experiments with their own tests (credential-isolation, nfs-subpath)
- `docs/` — architecture.md, auth.md, adding-a-service.md; read these before touching auth or service wiring

### Broker structure

One FastAPI process serves two surfaces: the FastMCP aggregator mounted at `/mcp` (speaks MCP-over-HTTP to LLM clients) and the `/v1` HTTP API. **`/v1` is the platform boundary** — the aggregator translates MCP calls into `/v1` calls, and everything behind `/v1` (aggregator choice, services, credential providers) is swappable implementation detail.

Four subsystems, each a package under `broker/src/af_mcp_broker/`:

1. **Identity** (`identity.py`) — the credential answers only "who is this?". Two kinds are accepted: a Keycloak JWT (`Authorization: Bearer`) and a broker-issued PAT (`mcp_pat_…`, `/mcp` only — `/v1` is JWT-only so a PAT cannot mint further PATs). Everything else about the principal — groups and POSIX uid/gid/unixname — is resolved from `PrincipalDirectory` via `PrincipalCache`, never from token claims. Broker is the sole token validator; no ForwardAuth proxy sits in front of the `/v1` or `/mcp` path, or the portal's HTML, on either host — the portal enforces its own client-side OIDC login (see `portal/src/lib/auth.ts`).
2. **Authorization** (`authorization/`) — declarative `policy.yaml` maps groups to permissions; each service's required permission comes from `services.yaml` (the registry is authoritative — `policy.yaml` no longer duplicates it). Groups come from the directory-backed principal cache, so Keycloak group changes take effect within one refresh window without any token-side mapper.
3. **Credentials** (`credentials/`) — provider classes (oidc, oauth21, x509, service) behind `CredentialProvider`; minted creds cached in-process by `(subject, target)` in `CredentialCache` with expiry sweeping. POSIX identity is optional and required only by x509.
4. **Audit** (`audit/`) — structlog JSON line per tool invocation + Prometheus metrics served on a dedicated port (9090, `METRICS_PORT`); the API port has no `/metrics`.

Configuration is file + env driven: `POLICY_FILE` and `SERVICES_FILE` (defaults under `/etc/af-mcp/`) are loaded at startup into `app.state` (see `app.py` lifespan); missing files degrade gracefully for local dev. Settings are pydantic-settings env vars in `config.py`.

### Adding a service requires no code

`ServiceRegistry` (`mcp/registry.py`) is driven by `services.yaml`; tools route to services by name prefix (`<prefix>_toolname`). The full operator procedure is config-only — see `docs/adding-a-service.md`.

### Critical auth constraint

Keycloak Standard Token Exchange (V2) mints tokens **accepted only by AF-internal services** — `atlas-auth.cern.ch` rejects them. Any credential for external ATLAS services (Rucio, PanDA, AMI) must use Keycloak's stored brokered token: `GET /realms/<realm>/broker/atlas-oidc/token` (IdP alias `atlas-oidc`, configurable via `OIDC_IDP_ALIAS`), which requires the user to have linked their CERN account. x509/VOMS proxies are minted via ephemeral k8s Jobs that NFS-subPath-mount the user's `~/.globus`. Details in `docs/auth.md` — do not conflate these paths.
