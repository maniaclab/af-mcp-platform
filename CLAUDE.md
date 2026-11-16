# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A credential-brokered MCP (Model Context Protocol) gateway for an analysis facility. LLM clients hit one broker endpoint; the broker authenticates them against the facility's Keycloak, checks authorization, brokers per-user credentials (IAM tokens, x509/VOMS proxies), and forwards tool calls to backend MCP servers (rucio-mcp, panda-mcp, ami-mcp, ...). LLM clients never hold raw credentials. The reference deployment is UChicago's ATLAS Analysis Facility (`mcp.af.uchicago.edu`); other facilities deploy the same chart with their own Keycloak realm, policy, and backend registry.

## Commands

Everything Python runs through [pixi](https://pixi.sh); dependencies live in `pixi.toml` (the broker's `pyproject.toml` intentionally declares no dependencies).

```bash
pixi run -e dev broker       # run broker locally with reload → http://localhost:8080/docs
pixi run test                # broker + skills tests in parallel (pytest broker/ skills/ -v -n auto; -n 0 to debug serially)
pixi run test-spikes         # spike validation tests (pytest spikes/ -v)
pixi run lint                # ruff check + format --check on broker/
pixi run fmt                 # ruff format + autofix
pixi run typecheck           # mypy broker/src
pixi run -e dev lint-imports # import-linter layer contracts (broker/pyproject.toml)
pixi run -e dev lint-all     # everything the CI lint job runs (ruff + import-linter + mypy + pre-commit)
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
- `spikes/` — validation experiments with their own tests (credential-isolation)
- `docs/` — architecture.md, auth.md, adding-a-service.md; read these before touching auth or service wiring

### Broker structure

One FastAPI process serves two surfaces: the FastMCP aggregator mounted at `/mcp` (speaks MCP-over-HTTP to LLM clients) and the `/v1` HTTP API. **`/v1` is the platform boundary** — the aggregator's middleware calls the same in-process functions the `/v1` route bodies call (it does not loop back over HTTP), and everything behind `/v1` (aggregator choice, services, credential providers) is swappable implementation detail.

Modules sit in fixed import layers, highest first: app (`app`, `token_sweep`, `__main__`) → `wiring` (the builders `app.lifespan` calls) → edges (`api` and `mcp`, independent of each other) → `pat_auth` → `identity` → `broker_state` (the typed state on `app.state.broker`) → features the edges share (`credmon`, `backend_client`, `service_status`, `lint_observations`, `maintenance`) → providers (`credentials`, `service_registry`) → `metering` → `otel_metrics` → `usage` → `audit` → platform (`tracing`, `principal_cache`, `mcp_auth_codes`, `authorization`) → stores (`principal_directory`, `token_registry`) → settings and infrastructure clients (`config`, `vault_kv`, `shared_state`, ...) → leaf modules with no first-party imports (`errors`, `constants`, `principal`, `http`, `logging`, `metrics`, ...). A module imports only from layers below its own, TYPE_CHECKING imports included; `pixi run -e dev lint-imports` (import-linter contracts in `broker/pyproject.toml`, part of `lint-all`) enforces it, and a new top-level module must be placed in a layer there. What `api` and `mcp` both need goes below them under public names. `Principal` and `PosixPrincipal` live in `principal.py`; `identity.py` only validates credentials, and the maintenance gate runs after it (`api/maintenance_gate.py` on `/v1`, `AsgiMaintenanceMiddleware` on `/mcp`). The layer diagram is in `docs/architecture.md` ("Import layers").

Four subsystems, each a package under `broker/src/af_mcp_broker/`:

1. **Identity** (`identity.py`) — the credential answers only "who is this?". Two kinds are accepted: a Keycloak JWT (`Authorization: Bearer`) and a broker-issued PAT (`mcp_pat_…`, `/mcp` only — `/v1` is JWT-only so a PAT cannot mint further PATs). Everything else about the principal — groups and POSIX uid/gid/unixname — is resolved from `PrincipalDirectory` via `PrincipalCache`, never from token claims. Broker is the sole token validator; no ForwardAuth proxy sits in front of the `/v1` or `/mcp` path, or the portal's HTML, on either host — the portal enforces its own client-side OIDC login (see `portal/src/lib/auth.ts`).
2. **Authorization** (`authorization/`) — declarative `policy.yaml` maps groups to permissions; each service's required permission comes from `services.yaml` (the registry is authoritative — `policy.yaml` no longer duplicates it). Groups come from the directory-backed principal cache, so Keycloak group changes take effect within one refresh window without any token-side mapper.
3. **Credentials** (`credentials/`) — provider classes (oidc, oauth21, x509, service) behind `CredentialProvider`; minted creds cached in-process by `(subject, target)` in `CredentialCache` with expiry sweeping. POSIX identity is optional on `Principal`; backends that need it (x509, condor, `requires_posix` identity tokens) take a `PosixPrincipal`, built once by `PosixPrincipal.from_principal`. Every entry that needs broker-signed identity tokens (x509 included) requires the signing key at boot; x509 also requires Vault.
4. **Audit** (`audit/`) — structlog JSON line per tool invocation + Prometheus metrics served on a dedicated port (9090, `METRICS_PORT`); the API port has no `/metrics`.

Configuration is file + env driven: `POLICY_FILE` and `SERVICES_FILE` (defaults under `/etc/af-mcp/`) are loaded at startup into the typed `BrokerState` on `app.state.broker` (see `app.py` lifespan, `broker_state.py`); a missing or empty `POLICY_FILE` (no group grants any permission) is a boot error, including under the dev bypass (the pixi `localdev` feature, used by the `dev` and `bypass` environments, points it at the dev policy in `authorization/policy.yaml`); a missing, invalid or empty `SERVICES_FILE` (no service defined) is a boot error too (`localdev` points it at the dev registry in `mcp/services.yaml`, which therefore holds only entries the documented local modes can satisfy: no `auth_type: x509` entry; the tests' x509 `ami` service lives in `broker/tests/data/`). Settings are pydantic-settings env vars in `config.py`.

### Adding a service requires no code

`ServiceRegistry` (`service_registry.py`) is driven by `services.yaml`; tools route to services by name prefix (`<prefix>_toolname`). The full operator procedure is config-only — see `docs/adding-a-service.md`.

### Critical auth constraint

Keycloak Standard Token Exchange (V2) mints tokens **accepted only by AF-internal services** — `atlas-auth.cern.ch` rejects them. Any credential for external ATLAS services (Rucio, PanDA, AMI) must use Keycloak's stored brokered token: `GET /realms/<realm>/broker/atlas-oidc/token` (IdP alias `atlas-oidc`, configurable via the `alias` of the `keycloak-brokered` entry in `IDENTITY_PROVIDERS` env var / `broker.identityProviders` chart value), which requires the user to have linked their CERN account. x509/VOMS proxies are minted by voms-token-service (the only component that mounts user homes; the broker sends it the user's POSIX identity and Globus passphrase) and persisted in Vault. Details in `docs/auth.md` — do not conflate these paths.
