# Testing

The broker's tests (`broker/tests/`) fall into three tiers. The tier is the
directory a test sits in; `broker/tests/conftest.py` turns that into a pytest
marker (`unit`, `integration`, `e2e`) when tests are collected, so no test
carries a marker by hand and `-m` selects a whole directory's worth.

| Tier | Directory | What a test may do | What it must not do |
| --- | --- | --- | --- |
| unit | `broker/tests/unit/` | Exercise one module (or a few that collaborate) through plain calls. Fakes are fine: in-memory stores, `httpx2.MockTransport`, fake Vault. | Boot the broker app or its lifespan, start a server, spawn a subprocess, run a helm render, need a postgres or redis binary. |
| integration | `broker/tests/integration/` | Boot the FastAPI app (`app_client*`, `TestClient`, `run_asgi_lifespan`), serve in-process ASGI or uvicorn backends and drive them with a real MCP client, run local postgres or redis, spawn subprocesses (helm renders, scripts, uvicorn). Everything stays on the machine running the tests. | Reach a network service the test did not start itself. |
| e2e | `broker/tests/e2e/` | Run against a deployed broker with a real Keycloak token and real backend services. No mocks, no fake JWKS, no in-process backends. | Run in the default `pixi run test` or CI; it needs a deployment and credentials. |

A test that needs the booted app is an integration test even when every
backend behind it is a fake: the booted app is the unit under test, and the
tests that cover it are the ones that find wiring mistakes. Where one subject
has both kinds of test, the module sits in the tier most of its tests belong to
and the rest go in a sibling named `<module>_unit.py` or
`<module>_integration.py` in the other directory; the sibling imports what the
two share from the module.

## Running a tier

```bash
pixi run test               # broker unit and integration tests, and skills (never e2e)
pixi run test-unit          # pytest broker/ -m unit
pixi run test-integration   # pytest broker/ -m integration
E2E_BROKER_URL=https://mcp.example.org pixi run test-e2e   # pytest broker/ -m e2e, needs MCP_BEARER_TOKEN too
pixi run -e dev pytest broker/tests/unit/test_config.py -v   # one file
```

`--strict-markers` is on, so a misspelt marker is an error rather than a
silently empty selection. `pytest -m "not integration"` is a quick pre-commit
loop; CI runs every tier.

## Helpers shared between test modules

Fixtures live in `broker/tests/conftest.py`; fakes and builders shared by many
modules live in plain modules beside it (`vault_fakes.py`, `signing_keys.py`,
`x509_fakes.py`, `broker_state_helpers.py`, and the `*_support.py` modules named
after the test module they serve). A test module never imports from another test
module; `test_no_cross_test_imports.py` enforces it. Test module basenames stay
unique across `unit/` and `integration/`.

## Tests outside `broker/tests/`

- `skills/*/tests/` tests the skill scripts. They start fixture MCP servers as
  subprocesses on the local machine, so by the definitions above they are
  integration tests; they are not marked, and run with `pixi run test`.
- `spikes/` holds validation spikes (`pixi run test-spikes`). They exercise the
  real `CredentialCache` in process, so they are unit-level.

## The e2e tier

`broker/tests/e2e/` and the `e2e` marker are reserved for tests that run
against a deployment. They are run by an operator after a release with
`pixi run test-e2e`, never in CI and never as part of `pixi run test` (which
deselects the marker). A test that fakes the identity provider or runs its
backend in process belongs under `integration/` however it is named.

The environment says which deployment and who to be; a test skips, naming the
missing variable, when a required one is unset:

| Variable | Meaning |
| --- | --- |
| `E2E_BROKER_URL` | Base URL of the deployed broker, e.g. `https://mcp.example.org` (a local dev-bypass broker works too). |
| `MCP_BEARER_TOKEN` | A real bearer token for it, a Keycloak access token or a PAT. Read it with `read -s` so it never lands in shell history or a file. |
| `E2E_TOOL` | Optional. A read-only tool that takes no arguments, to call and to require in `tools/list`; defaults to the gateway's own `af_whoami`. Name a backend's tool (e.g. `rucio_whoami`) to prove the broker reaches it. |

`test_mcp_flow.py` runs what a real MCP client does over the wire through the
`fastmcp` client: initialize, `tools/list` (what is visible reflects the
caller's groups) and one read-only `tools/call`. Linking an identity or
unlocking a credential first is the operator's job: a call that fails with
"not linked" or "Authorization denied" is the deployment telling you the
caller's state, not a test bug.
