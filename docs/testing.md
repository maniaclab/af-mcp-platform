# Testing

The broker's tests (`broker/tests/`) fall into three tiers. The tier is the
directory a test sits in; `broker/tests/conftest.py` turns that into a pytest
marker (`unit`, `integration`, `e2e`) when tests are collected, so no test
carries a marker by hand and `-m` selects a whole directory's worth.

| Tier | Directory | What a test may do | What it must not do |
| --- | --- | --- | --- |
| unit | `broker/tests/unit/` | Exercise one module (or a few that collaborate) through plain calls. Fakes are fine: in-memory stores, `httpx2.MockTransport`, fake Vault. | Boot the broker app or its lifespan, start a server, spawn a subprocess, run a helm render, need a postgres or redis binary. |
| integration | `broker/tests/integration/` | Boot the FastAPI app (`app_client*`, `TestClient`, `run_asgi_lifespan`), serve in-process ASGI or uvicorn backends and drive them with a real MCP client, run local postgres or redis, spawn subprocesses (helm renders, scripts, uvicorn). Everything stays on the machine running the tests. | Reach a network service the test did not start itself. |
| e2e | `broker/tests/e2e/` | Run against a deployed broker with a real Keycloak token and real backend services. No mocks, no fake JWKS, no in-process backends. | Run in the default `pixi run test`; it needs a deployment and credentials. |

A test that needs the booted app is an integration test even when every
backend behind it is a fake: the booted app is the unit under test, and the
tests that cover it are the ones that find wiring mistakes. Where one subject
has both kinds of test, the module sits in the tier most of its tests belong to
and the rest go in a sibling named `<module>_unit.py` or
`<module>_integration.py` in the other directory; the sibling imports what the
two share from the module.

## Running a tier

```bash
pixi run test               # everything: broker (all tiers) and skills
pixi run test-unit          # pytest broker/ -m unit
pixi run test-integration   # pytest broker/ -m integration
pixi run -e dev pytest broker/tests/unit/test_config.py -v   # one file
```

`--strict-markers` is on, so a misspelt marker is an error rather than a
silently empty selection. `pytest -m "not integration"` is a quick pre-commit
loop; CI runs every tier.

## Helpers shared between test modules

Fixtures live in `broker/tests/conftest.py`; fakes and builders shared by many
modules live in plain modules beside it (`vault_fakes.py`, `signing_keys.py`,
`x509_fakes.py`, `broker_state_helpers.py`). Some test modules also import
helpers from one another by module name (`from test_broker_issued import ...`).
`tests/unit` and `tests/integration` are both on pytest's `pythonpath`, and test
module basenames are unique across them, so that works from either tier.

## Tests outside `broker/tests/`

- `skills/*/tests/` tests the skill scripts. They start fixture MCP servers as
  subprocesses on the local machine, so by the definitions above they are
  integration tests; they are not marked, and run with `pixi run test`.
- `spikes/` holds validation spikes (`pixi run test-spikes`). They exercise the
  real `CredentialCache` in process, so they are unit-level.
- `scripts/verify-mcp-flow.py` is an end-to-end check, run by hand against a
  deployed broker with a real bearer token (see its docstring). It is the
  closest thing to the e2e tier today; it is not a pytest test.

## The e2e tier

`broker/tests/e2e/` and the `e2e` marker are reserved for tests that run
against a deployment: they take the broker URL and a bearer token from the
environment (`MCP_BEARER_TOKEN`, as `scripts/verify-mcp-flow.py` does), skip
themselves when those are absent, and are run by an operator after a
release, never as part of `pixi run test` or CI. A test that fakes the
identity provider or runs its backend in process belongs under `integration/`
however it is named.
