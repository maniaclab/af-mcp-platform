# Admin Capabilities Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a config-driven admin group with a reusable gating helper, an
admin view of another user's usage, and a broker-wide maintenance mode
enforced on both `/v1` and `/mcp` (JWT and PAT) — per
`docs/plans/2026-08-28-admin-capabilities-design.md`.

**Architecture:** `Settings.admin_group` + `is_admin()` (authorization/base.py)
+ a `require_admin` FastAPI dependency gate every admin-only route.
`UsageStore` gains `list_subjects()` across both backends, backing a new
admin-only `GET /v1/usage/subjects` and an admin override on `GET
/v1/usage?subject=`. A new `MaintenanceModeStore` ABC (in_memory/vault/
postgres, mirroring `TokenRegistryBackend`/`UsageStore`'s shape) backs a
`require_not_in_maintenance` dependency on `/v1` routers and a matching
check inside `/mcp`'s `AsgiAuthMiddleware`, admin-bypassed either way.

**Tech Stack:** FastAPI, pydantic-settings, asyncpg, Vault/OpenBao KV-v2
(httpx), FastMCP middleware, Astro/Vue portal.

---

## Ground rules for every task below

- Run tests with `pixi run -e dev pytest broker/tests/<file> -v` (broker) or
  `pixi run -e portal test` (portal — check `portal/package.json` for the
  exact script name before Task P1).
- Every new Vault-backed unit test fakes Vault's HTTP API via
  `httpx.MockTransport`, following `broker/tests/test_token_registry.py`'s
  `_FakeRegistryVault` pattern — this is a unit test of the KV-v2 wire
  protocol, not an end-to-end test, so a fake transport is the established
  convention here, not a violation of the no-mocks-in-integration-tests rule.
- Every new Postgres-backed unit test uses a **real** ephemeral postgres via
  the `postgres_dsn` fixture (moved to `conftest.py` in Task B2) — no mocks,
  following `broker/tests/test_usage_postgres.py`'s existing pattern exactly.
- Commit after each task (or sub-group of tightly related tasks) with a
  Conventional Commits message, `Assisted-by: Claude (Anthropic)` trailer,
  from inside `.worktrees/admin-capabilities`.

---

# Part A — Admin gating

### Task A1: `Settings.admin_group`

**Files:**
- Modify: `broker/src/af_mcp_broker/config.py`
- Test: `broker/tests/test_config.py`

**Step 1: Write the failing test** — append near the other backend-selection
tests in `test_config.py`:

```python
# ---------------------------------------------------------------------------
# Admin group (admin gating -- 2026-08-28 admin capabilities design)
# ---------------------------------------------------------------------------


def test_admin_group_defaults_to_empty():
    settings = Settings()
    assert settings.admin_group == ""
```

**Step 2: Run test to verify it fails**

Run: `pixi run -e dev pytest broker/tests/test_config.py::test_admin_group_defaults_to_empty -v`
Expected: FAIL — `AttributeError` (or the default is simply absent).

Actually this will currently pass trivially since pydantic raises on unknown
kwargs only, and reading a nonexistent attribute is what fails — confirm you
see an `AttributeError: 'Settings' object has no attribute 'admin_group'`.

**Step 3: Write minimal implementation** — add next to `builtin_service_name`
in `config.py` (same section, same style):

```python
    # Keycloak group whose members see and can use every admin-only broker
    # surface (require_admin dependency, authorization/base.py's is_admin) --
    # 2026-08-28 admin capabilities design. Empty means no admin surface is
    # reachable by anyone: fail closed, no magic default group name.
    admin_group: str = ""
```

**Step 4: Run test to verify it passes**

Run: `pixi run -e dev pytest broker/tests/test_config.py::test_admin_group_defaults_to_empty -v`
Expected: PASS

**Step 5: Commit**

```bash
cd .worktrees/admin-capabilities
git add broker/src/af_mcp_broker/config.py broker/tests/test_config.py
git commit -m "$(cat <<'EOF'
feat(broker): add Settings.admin_group

Empty by default -- no admin surface is reachable until an operator
configures which Keycloak group is the admin group.

Assisted-by: Claude (Anthropic)
EOF
)"
```

---

### Task A2: `is_admin()` helper

**Files:**
- Modify: `broker/src/af_mcp_broker/authorization/base.py`
- Test: create `broker/tests/test_authorization.py` if it doesn't already
  exist — check first with `ls broker/tests/test_authorization*.py`; if a
  file already covers `get_principal_permissions`/`check_entitlement`, add
  to it instead of creating a new one.

**Step 1: Write the failing test**

```python
from af_mcp_broker.authorization.base import is_admin
from af_mcp_broker.config import Settings


def test_is_admin_true_when_member_of_configured_admin_group(make_principal):
    settings = Settings(admin_group="af-admins")
    principal = make_principal(groups=["atlas", "af-admins"])
    assert is_admin(principal, settings) is True


def test_is_admin_false_when_not_a_member(make_principal):
    settings = Settings(admin_group="af-admins")
    principal = make_principal(groups=["atlas"])
    assert is_admin(principal, settings) is False


def test_is_admin_false_when_admin_group_unconfigured(make_principal):
    settings = Settings(admin_group="")
    principal = make_principal(groups=["af-admins"])
    assert is_admin(principal, settings) is False
```

(`make_principal` is the existing `conftest.py` fixture — see
`broker/tests/conftest.py:454`.)

**Step 2: Run test to verify it fails**

Run: `pixi run -e dev pytest broker/tests/test_authorization.py -k is_admin -v`
Expected: FAIL — `ImportError: cannot import name 'is_admin'`

**Step 3: Write minimal implementation** — add to
`broker/src/af_mcp_broker/authorization/base.py`, near
`get_principal_permissions` (needs `Settings` only via `TYPE_CHECKING`,
matching how `Principal` is already imported there):

```python
if TYPE_CHECKING:
    from af_mcp_broker.config import Settings
    from af_mcp_broker.identity import Principal
```

(extend the existing `TYPE_CHECKING` block rather than duplicating it — the
file already has `if TYPE_CHECKING: from af_mcp_broker.identity import
Principal` at the top; add the `Settings` import to that same block.)

```python
def is_admin(principal: Principal, settings: Settings) -> bool:
    """Return True when *principal* belongs to the configured admin group.

    Deliberately separate from the permission engine's ``group_permissions``
    -- "can this principal manage the platform" is a different axis than "can
    this principal call this tool", and maintenance mode (see maintenance.py)
    needs this same check to bypass an otherwise-universal gate, which
    doesn't fit the permission model. An empty ``admin_group`` (the default)
    means no admin surface is reachable by anyone.
    """
    return bool(settings.admin_group) and settings.admin_group in principal.groups
```

**Step 4: Run test to verify it passes**

Run: `pixi run -e dev pytest broker/tests/test_authorization.py -k is_admin -v`
Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add broker/src/af_mcp_broker/authorization/base.py broker/tests/test_authorization*.py
git commit -m "$(cat <<'EOF'
feat(broker): add is_admin() helper

Checks admin-group membership directly, deliberately separate from the
permission engine -- platform administration is a different axis than a
service permission, and maintenance mode needs the same check.

Assisted-by: Claude (Anthropic)
EOF
)"
```

---

### Task A3: `require_admin` FastAPI dependency

**Files:**
- Modify: `broker/src/af_mcp_broker/identity.py`
- Test: create `broker/tests/test_require_admin.py`

**Step 1: Write the failing test** — a minimal FastAPI app so this test
doesn't depend on any real admin route existing yet:

```python
"""Tests for identity.require_admin -- the admin-gating dependency (2026-08-28 admin capabilities design)."""

from __future__ import annotations

import json
from typing import Annotated

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from af_mcp_broker.config import get_settings
from af_mcp_broker.identity import Principal, keycloak_dependency, require_admin


@pytest.fixture
def admin_test_app(monkeypatch: pytest.MonkeyPatch, make_principal):
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")
    get_settings.cache_clear()

    app = FastAPI()

    @app.get("/probe")
    async def probe(principal: Annotated[Principal, Depends(require_admin)]) -> dict:
        return {"subject": principal.subject}

    state = {"principal": make_principal(groups=["atlas"])}
    app.dependency_overrides[keycloak_dependency] = lambda: state["principal"]
    with TestClient(app) as client:
        yield client, state
    app.dependency_overrides.clear()
    get_settings.cache_clear()


def test_admin_member_is_allowed(admin_test_app, make_principal):
    client, state = admin_test_app
    state["principal"] = make_principal(groups=["atlas", "af-admins"])
    resp = client.get("/probe")
    assert resp.status_code == 200


def test_non_admin_is_403(admin_test_app):
    client, _state = admin_test_app
    resp = client.get("/probe")
    assert resp.status_code == 403
```

**Step 2: Run test to verify it fails**

Run: `pixi run -e dev pytest broker/tests/test_require_admin.py -v`
Expected: FAIL — `ImportError: cannot import name 'require_admin'`

**Step 3: Write minimal implementation** — add to `identity.py`, right after
`keycloak_dependency`:

```python
async def require_admin(
    principal: Annotated[Principal, Depends(keycloak_dependency)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Principal:
    """FastAPI dependency: 403s unless *principal* is in ``settings.admin_group``.

    Depends on ``keycloak_dependency`` so every admin route gets identity
    resolution AND admin-group enforcement from one dependency -- inject this
    in place of ``keycloak_dependency`` on any admin-only route:

        @router.post("/admin/example")
        async def example(
            principal: Annotated[Principal, Depends(require_admin)],
        ):
            ...
    """
    if not is_admin(principal, settings):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires membership in the admin group.",
        )
    return principal
```

Add the import at the top of `identity.py`:

```python
from af_mcp_broker.authorization.base import is_admin
```

Check this doesn't create a circular import (`authorization/base.py` only
imports `Principal` under `TYPE_CHECKING`, so it's safe) by running the full
test file once implemented.

**Step 4: Run test to verify it passes**

Run: `pixi run -e dev pytest broker/tests/test_require_admin.py -v`
Expected: PASS (2 tests)

**Step 5: Commit**

```bash
git add broker/src/af_mcp_broker/identity.py broker/tests/test_require_admin.py
git commit -m "$(cat <<'EOF'
feat(broker): add require_admin FastAPI dependency

Depends on keycloak_dependency so an admin route gets identity resolution
and admin-group enforcement from one Depends(require_admin) call.

Assisted-by: Claude (Anthropic)
EOF
)"
```

---

### Task A4: `IdentitiesResponse.is_admin`

**Files:**
- Modify: `broker/src/af_mcp_broker/api/identities.py`
- Test: locate the existing identities route test (run
  `grep -rl "get_identities\|/v1/identities" broker/tests/*.py` to find it —
  likely `test_identities_api.py` or similar) and add to it.

**Step 1: Write the failing test** — add alongside the existing
`GET /v1/identities` route tests, reusing whatever app/client fixture they
already use (likely `app_client_factory` from `conftest.py`):

```python
def test_is_admin_true_for_admin_group_member(app_client_factory, monkeypatch):
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")
    with app_client_factory() as (client, state):
        state["principal"] = state["principal"].__class__(
            **{**state["principal"].__dict__, "groups": ["atlas", "af-admins"]}
        )
        resp = client.get("/v1/identities")
        assert resp.json()["is_admin"] is True


def test_is_admin_false_for_non_member(app_client_factory, monkeypatch):
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")
    with app_client_factory() as (client, state):
        resp = client.get("/v1/identities")
        assert resp.json()["is_admin"] is False
```

Before writing this, actually read the real test file found by the grep
above and match its existing style/fixtures exactly — `Principal` is a
frozen dataclass, so if the file already has a helper for building a
principal with different groups (or uses `make_principal` re-assigned onto
`state["principal"]`), use that instead of the `__dict__` workaround above,
which is only a placeholder for this plan.

**Step 2: Run test to verify it fails**

Run: `pixi run -e dev pytest <the file> -k is_admin -v`
Expected: FAIL — `KeyError: 'is_admin'`

**Step 3: Write minimal implementation** — in
`broker/src/af_mcp_broker/api/identities.py`:

```python
class IdentitiesResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    email: str
    unixname: str | None
    uid: int | None
    gid: int | None
    groups: list[str]
    providers: list[IdentityProvider]
    # True when the caller is a member of Settings.admin_group -- gates the
    # portal's Admin nav entry and admin-only views (2026-08-28 admin
    # capabilities design). False whenever admin_group is unconfigured.
    is_admin: bool
```

```python
@router.get("", response_model=IdentitiesResponse, summary="Get caller identity")
async def get_identities(
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
) -> IdentitiesResponse:
    providers = await _build_providers(request, principal)
    settings = getattr(request.app.state, "settings", None) or get_settings()
    return IdentitiesResponse(
        subject=principal.subject,
        email=principal.email,
        unixname=principal.unixname,
        uid=principal.uid,
        gid=principal.gid,
        groups=principal.groups,
        providers=providers,
        is_admin=is_admin(principal, settings),
    )
```

Add imports: `from af_mcp_broker.authorization.base import is_admin` and
`from af_mcp_broker.config import get_settings` (check whether `get_settings`
is already imported in this file first — it likely isn't, since the router
currently reads settings only via `request.app.state`).

**Step 4: Run test to verify it passes**

Run: `pixi run -e dev pytest <the file> -k is_admin -v`
Expected: PASS

**Step 5: Commit**

```bash
git add broker/src/af_mcp_broker/api/identities.py broker/tests/<the file>
git commit -m "$(cat <<'EOF'
feat(broker): surface is_admin on GET /v1/identities

The portal already fetches /v1/identities on every authenticated page
load, so this is the one place to learn whether to show admin UI --
no new endpoint needed.

Assisted-by: Claude (Anthropic)
EOF
)"
```

---

### Task A5: Chart wiring for `admin_group`

**Files:**
- Modify: `charts/af-mcp-platform/values.yaml`
- Modify: `charts/af-mcp-platform/templates/_helpers.tpl`

**Step 1** — in `values.yaml`, add next to `builtinServiceName` (around line
72):

```yaml
  # Keycloak group whose members see and can use admin-only broker surfaces
  # (2026-08-28 admin capabilities design: the Admin portal page, the
  # usage-for-other-users view, maintenance mode). Empty means no admin
  # surface is reachable by anyone.
  adminGroup: ""
```

**Step 2** — in `_helpers.tpl`, add next to the `USAGE_STORE_BACKEND` block
(after line 355's closing `{{- end }}` at line 367, before the tracing
block):

```yaml
{{- if .Values.broker.adminGroup }}
# Admin group (2026-08-28 admin capabilities design) -- gates require_admin
# and every admin-only /v1 route. Only rendered when set; unset means no
# admin surface is reachable by anyone.
- name: ADMIN_GROUP
  value: {{ .Values.broker.adminGroup | quote }}
{{- end }}
```

**Step 3: Verify the chart still lints**

Run: `helm lint charts/af-mcp-platform`
Expected: no new errors/warnings.

**Step 4: Commit**

```bash
git add charts/af-mcp-platform/values.yaml charts/af-mcp-platform/templates/_helpers.tpl
git commit -m "$(cat <<'EOF'
feat(chart): wire broker.adminGroup to ADMIN_GROUP

Assisted-by: Claude (Anthropic)
EOF
)"
```

---

### Task A6: Portal — surface `is_admin`, gate an Admin nav entry

**Files:**
- Modify: `portal/src/lib/api.ts`
- Modify: `portal/src/layouts/Base.astro`
- Create: `portal/src/pages/admin.astro`
- Create: `portal/src/components/AdminPage.vue`
- Test: `portal/src/components/__tests__/AdminPage.test.ts`

**Step 1** — read `portal/src/lib/api.ts:179-260` (`IdentityProvider`/
`IdentitiesResponse`/`fetchIdentities`) in full before editing, to match its
exact style.

**Step 2: Write the failing test** — `AdminPage.vue` doesn't exist yet, so
start with the simplest possible render test, following whichever pattern
`portal/src/components/__tests__/IdentitiesPage.test.ts` uses (Vue Test
Utils `mount`, presumably):

```typescript
import { describe, expect, it } from 'vitest'; // or whatever runner IdentitiesPage.test.ts imports -- match it exactly
import { mount } from '@vue/test-utils';
import AdminPage from '../AdminPage.vue';

describe('AdminPage', () => {
  it('renders a heading', () => {
    const wrapper = mount(AdminPage);
    expect(wrapper.text()).toContain('Admin');
  });
});
```

**Step 3: Run test to verify it fails**

Run: `pixi run -e portal test -- AdminPage` (confirm the actual script name
in `portal/package.json` first — this plan assumes a `test` script exists,
matching the CLAUDE.md-documented `pixi run -e dev lint-all`/`pixi run
--environment dev test` pattern already seen for the broker; check
`portal/package.json`'s `scripts` block and adjust the command if it differs,
e.g. `npm run test` inside the portal dir).

Expected: FAIL — module not found.

**Step 4: Write minimal implementation**

In `portal/src/lib/api.ts`, add `is_admin: boolean;` to the
`IdentitiesResponse` interface (matching the field name exactly, snake_case
like every other field in that interface — the broker's pydantic model uses
snake_case and the portal doesn't rename it, per the existing interfaces in
this file).

Create `portal/src/components/AdminPage.vue` as a minimal shell for now
(items B5 and C11 below add real content to it):

```vue
<script setup lang="ts">
</script>

<template>
  <section class="af-panel">
    <h1>Admin</h1>
    <p class="af-dim">Platform administration.</p>
  </section>
</template>
```

Create `portal/src/pages/admin.astro`, matching `portal/src/pages/usage.astro`'s
structure exactly (read that file first — it's almost certainly a thin
wrapper: `Base.astro` layout + mount the page's root Vue component). Mirror
its frontmatter/imports, swapping in `AdminPage.vue`.

In `portal/src/layouts/Base.astro`, find the `navGroups` array (line ~29)
and the client-side hydration script that fetches identities/pins nav badges
(around line 584-707). Add an `"Admin"` entry to the appropriate nav group
with `hidden` set by default (matching how `af-sidebar__badge` elements start
`hidden` and get revealed by the mount script) or gated the way `dashboard
summary` conditionally shows things — read that mount script in full before
choosing the exact mechanism, since Base.astro is a static Astro
component (no per-request server auth state), so this must be a client-side
DOM reveal after `fetchIdentities()` resolves, exactly like the existing
badge-pinning code does. Concretely: add
`<a href="/admin/" data-af-admin-nav hidden>Admin</a>` next to the other nav
`<a>` entries, then in the mount script:

```typescript
import { fetchIdentities } from '../lib/api';
// ... inside the existing mount/init function, alongside the dashboard-summary fetch:
fetchIdentities()
  .then((identities) => {
    if (identities.is_admin) {
      document
        .querySelectorAll<HTMLElement>('[data-af-admin-nav]')
        .forEach((el) => el.removeAttribute('hidden'));
    }
  })
  .catch(() => {
    // Admin nav stays hidden — same fail-safe posture as navBadges(null).
  });
```

Check whether `fetchIdentities()` is already called elsewhere on every page
load (it likely is, for the greeting/unixname display mentioned in the
comment at line 584) — if so, reuse that existing call's result instead of
issuing a second `/v1/identities` request.

**Step 5: Run test to verify it passes**

Run the portal test command again.
Expected: PASS.

**Step 6: Manually verify in the browser** — per this repo's CLAUDE.md, a
portal/frontend change must be exercised in a real browser before being
called done:

```bash
pixi run broker      # terminal 1
pixi run -e portal dev   # terminal 2
```

Visit `http://localhost:4321/admin/` while authenticated as a
`BROKER_DEV_INSECURE_PRINCIPAL` principal whose `groups` includes whatever
`ADMIN_GROUP` you set locally (see `docs/local-development.md`), confirm the
nav entry appears and the page renders; then remove the admin group from the
dev-bypass principal's groups and confirm the nav entry disappears and
`/admin/` is at least inert (full access-denial UI is out of scope for this
task — that's the actual admin content added in later tasks).

**Step 7: Commit**

```bash
git add portal/src/lib/api.ts portal/src/layouts/Base.astro portal/src/pages/admin.astro portal/src/components/AdminPage.vue portal/src/components/__tests__/AdminPage.test.ts
git commit -m "$(cat <<'EOF'
feat(portal): add admin-gated nav entry and Admin page shell

is_admin comes from GET /v1/identities, revealed client-side the same
way nav badges already are -- Base.astro is a static shell with no
per-request server auth state.

Assisted-by: Claude (Anthropic)
EOF
)"
```

---

# Part B — Admin usage view for other users

### Task B1: `UsageStore.list_subjects()` — ABC + in-memory

**Files:**
- Modify: `broker/src/af_mcp_broker/usage/store.py`
- Test: `broker/tests/test_usage_store.py`

**Step 1: Write the failing test** — add to `test_usage_store.py`:

```python
async def test_list_subjects_returns_distinct_subjects_in_window():
    store = InMemoryUsageStore()
    await store.record(_record(principal_sub="alice"))
    await store.record(_record(principal_sub="bob"))
    await store.record(_record(principal_sub="alice"))

    subjects = await store.list_subjects(days=30)

    assert sorted(subjects) == ["alice", "bob"]


async def test_list_subjects_excludes_outside_window():
    store = InMemoryUsageStore()
    old_ts = (datetime.now(tz=UTC) - timedelta(days=90)).timestamp()
    await store.record(_record(principal_sub="stale", timestamp=old_ts))

    assert await store.list_subjects(days=30) == []
```

Check `test_usage_store.py`'s existing `_record()` helper (or import one from
`test_usage_postgres.py`/`test_usage_api.py`'s shape) for the exact
`AuditRecord` field set; add `timestamp`/`principal_sub` overrides as shown.

**Step 2: Run test to verify it fails**

Run: `pixi run -e dev pytest broker/tests/test_usage_store.py -k list_subjects -v`
Expected: FAIL — `AttributeError: 'InMemoryUsageStore' object has no attribute 'list_subjects'`

**Step 3: Write minimal implementation** — in
`broker/src/af_mcp_broker/usage/store.py`:

```python
class UsageStore(abc.ABC):
    ...

    @abc.abstractmethod
    async def list_subjects(self, days: int) -> list[str]:
        """Return distinct principal subjects with recorded usage in the trailing *days*-day window.

        Backs the admin-only usage-for-other-users view (2026-08-28 admin
        capabilities design) -- this only ever lists people with broker
        activity, never a full Keycloak user directory.
        """
```

```python
class InMemoryUsageStore(UsageStore):
    ...

    async def list_subjects(self, days: int) -> list[str]:
        start = window_start(days)
        return sorted({sub for (sub, day, _s, _m, _o) in self._counters if day >= start})
```

**Step 4: Run test to verify it passes**

Run: `pixi run -e dev pytest broker/tests/test_usage_store.py -k list_subjects -v`
Expected: PASS (2 tests)

Note: `UsageStore` is now an ABC with a new abstract method — this will break
`PostgresUsageStore` (it becomes uninstantiable) until Task B2. Run the full
test suite once to confirm `test_usage_postgres.py` now fails with
`TypeError: Can't instantiate abstract class PostgresUsageStore` — expected,
fixed next.

**Step 5: Commit** (bundle with B2 — see below; don't commit a broken ABC on
its own).

---

### Task B2: `PostgresUsageStore.list_subjects()`, and move `postgres_dsn` to `conftest.py`

**Files:**
- Modify: `broker/src/af_mcp_broker/usage/postgres.py`
- Modify: `broker/tests/conftest.py` (add the `postgres_dsn` fixture)
- Modify: `broker/tests/test_usage_postgres.py` (remove its now-duplicate
  local `postgres_dsn` fixture, keep using the conftest one — pytest fixtures
  are visible project-wide with no import needed)
- Test: `broker/tests/test_usage_postgres.py`

**Step 1: Move the fixture** — cut the `postgres_dsn` fixture (lines 50-97 of
`test_usage_postgres.py`, shown above) verbatim into `broker/tests/conftest.py`
(near the other session-scoped fixtures), including its imports (`shutil`,
`subprocess`, `find_available_port` from `fastmcp.utilities.http`) — check
`conftest.py`'s existing imports first and only add what's missing. Leave
`test_usage_postgres.py`'s `store` fixture and everything else in place; only
the `postgres_dsn` definition moves.

Run the full existing suite once to confirm nothing broke from the move:

Run: `pixi run -e dev pytest broker/tests/test_usage_postgres.py -v`
Expected: same pass count as before the move — this step is a pure refactor,
not new behavior. (`PostgresUsageStore` is still missing `list_subjects`, so
if Task B1 has already landed, expect the same abstract-class failures as its
Step 4 noted — that's fine, both get fixed together below.)

**Step 2: Write the failing test** — add to `test_usage_postgres.py`:

```python
async def test_list_subjects_returns_distinct_subjects_in_window(
    store: PostgresUsageStore,
) -> None:
    await store.record(_record(principal_sub="alice"))
    await store.record(_record(principal_sub="bob", audit_id="audit-2"))
    await store.record(_record(principal_sub="alice", audit_id="audit-3"))

    subjects = await store.list_subjects(days=30)

    assert sorted(subjects) == ["alice", "bob"]
```

(`_record()`'s default `timestamp` is `datetime.now(...)`, so no override
needed for the in-window case; check whether the existing `_record()` helper
already accepts an `audit_id` override — `af_mcp_usage_events`'s primary key
is `audit_id`, so each call above needs a distinct one or the second/third
insert is silently dropped by `ON CONFLICT DO NOTHING`.)

**Step 3: Run test to verify it fails**

Run: `pixi run -e dev pytest broker/tests/test_usage_postgres.py -k list_subjects -v`
Expected: FAIL — `AttributeError`, or (if B1 already landed) a collection
error from the still-abstract class.

**Step 4: Write minimal implementation** — in
`broker/src/af_mcp_broker/usage/postgres.py`, add a query constant next to
`_QUERY`:

```python
_LIST_SUBJECTS_QUERY = """
SELECT DISTINCT principal_sub
FROM af_mcp_usage_events
WHERE (ts AT TIME ZONE 'UTC')::date >= $1
"""
```

```python
    async def list_subjects(self, days: int) -> list[str]:
        rows = await self._require_pool().fetch(
            _LIST_SUBJECTS_QUERY, window_start(days)
        )
        return sorted(row["principal_sub"] for row in rows)
```

**Step 5: Run test to verify it passes**

Run: `pixi run -e dev pytest broker/tests/test_usage_postgres.py -v`
Expected: PASS, full file, no abstract-class errors.

Also re-run: `pixi run -e dev pytest broker/tests/test_usage_store.py -v`
Expected: PASS (Task B1's tests too).

**Step 6: Commit** (covers B1 + B2 together, since B1 alone leaves the ABC
uninstantiable):

```bash
git add broker/src/af_mcp_broker/usage/store.py broker/src/af_mcp_broker/usage/postgres.py broker/tests/test_usage_store.py broker/tests/test_usage_postgres.py broker/tests/conftest.py
git commit -m "$(cat <<'EOF'
feat(broker): add UsageStore.list_subjects() across both backends

Backs the admin usage-for-other-users view: distinct subjects with
recorded activity in a trailing window, never a full Keycloak user
directory. Moved the postgres_dsn test fixture to conftest.py so the
upcoming maintenance-mode postgres backend tests can reuse it too.

Assisted-by: Claude (Anthropic)
EOF
)"
```

---

### Task B3: `GET /v1/usage?subject=` admin override

**Files:**
- Modify: `broker/src/af_mcp_broker/api/usage.py`
- Test: `broker/tests/test_usage_api.py`

**Step 1: Write the failing test** — read `test_usage_api.py`'s existing
`client`/principal fixtures in full first (it's not `app_client_factory` —
grep the top of the file for its actual fixture, since it directly seeds
`client.app.state.usage_store`). Add:

```python
def test_subject_param_rejected_for_non_admin(client: TestClient) -> None:
    resp = client.get("/v1/usage", params={"subject": "someone-else"})
    assert resp.status_code == 422


def test_subject_param_allowed_for_admin(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")
    # ... set the test's principal's groups to include "af-admins" -- follow
    # whatever mechanism this file's fixtures already use (likely a
    # dependency_override on keycloak_dependency, matching conftest.py's
    # app_client_factory shape, or its own local variant -- read the file
    # before writing this).
    _seed(client, _record(principal_sub="someone-else"))
    resp = client.get("/v1/usage", params={"subject": "someone-else"})
    assert resp.status_code == 200
    assert resp.json()["subject"] == "someone-else"
```

**Step 2: Run test to verify it fails**

Run: `pixi run -e dev pytest broker/tests/test_usage_api.py -k subject_param -v`
Expected: FAIL — a `subject` query param is currently silently ignored (no
422, and the response is always scoped to the caller).

**Step 3: Write minimal implementation** — in `api/usage.py`:

```python
async def get_usage(
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
    days: Annotated[int, Query(ge=1, le=365)] = 30,
    model: str | None = None,
    subject: str | None = None,
) -> UsageResponse:
    """..."""  # extend the existing docstring with a line about `subject`
    settings = getattr(request.app.state, "settings", None) or get_settings()

    if subject is not None and not is_admin(principal, settings):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="The subject parameter requires admin-group membership.",
        )
    effective_subject = subject if subject is not None else principal.subject

    store: UsageStore | None = getattr(request.app.state, "usage_store", None)
    try:
        return await build_usage_summary(
            store, effective_subject, days, model, settings.cost_reference_model
        )
    except UnknownCostModelError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
```

Add `from af_mcp_broker.authorization.base import is_admin` to the imports.

**Step 4: Run test to verify it passes**

Run: `pixi run -e dev pytest broker/tests/test_usage_api.py -v`
Expected: PASS, full file (confirm no regression on the existing self-service
tests).

**Step 5: Commit**

```bash
git add broker/src/af_mcp_broker/api/usage.py broker/tests/test_usage_api.py
git commit -m "$(cat <<'EOF'
feat(broker): admin subject override on GET /v1/usage

A non-admin caller passing ?subject= gets 422; an admin gets that
subject's usage instead of their own. Response shape unchanged.

Assisted-by: Claude (Anthropic)
EOF
)"
```

---

### Task B4: `GET /v1/usage/subjects` (admin-only, resolved to unixname/email)

**Files:**
- Modify: `broker/src/af_mcp_broker/api/usage.py`
- Test: `broker/tests/test_usage_api.py`

**Step 1: Write the failing test**

```python
def test_usage_subjects_requires_admin(client: TestClient) -> None:
    resp = client.get("/v1/usage/subjects")
    assert resp.status_code == 403


def test_usage_subjects_resolves_unixname(
    client: TestClient, monkeypatch, static_principal_cache
) -> None:
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")
    cache, directory = static_principal_cache
    directory.groups_by_subject["someone-else"] = ["atlas"]
    directory.posix_by_subject["someone-else"] = {"unixname": "sperson"}
    # wire `cache` onto the test app's state, and set the caller's groups to
    # include "af-admins" -- follow this file's existing fixture mechanism.
    _seed(client, _record(principal_sub="someone-else"))

    resp = client.get("/v1/usage/subjects")

    assert resp.status_code == 200
    assert {"subject": "someone-else", "unixname": "sperson", "email": ""} in resp.json()["subjects"]
```

Adjust field names/shape once you see how this test file wires
`principal_cache` onto `client.app.state` (it may need a small addition to
this file's own client fixture if none of the existing tests already touch
`principal_cache` — check `test_usage_api.py`'s fixture definition first).

**Step 2: Run test to verify it fails**

Run: `pixi run -e dev pytest broker/tests/test_usage_api.py -k usage_subjects -v`
Expected: FAIL — 404 (route doesn't exist).

**Step 3: Write minimal implementation** — in `api/usage.py`:

```python
class UsageSubject(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    unixname: str | None
    email: str


class UsageSubjectsResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    subjects: list[UsageSubject]


@router.get(
    "/subjects",
    response_model=UsageSubjectsResponse,
    summary="List subjects with recorded usage (admin only)",
)
async def get_usage_subjects(
    request: Request,
    principal: Annotated[Principal, Depends(require_admin)],
    days: Annotated[int, Query(ge=1, le=365)] = 30,
) -> UsageSubjectsResponse:
    """Admin-only: distinct subjects with usage in the trailing window, resolved to unixname/email for display.

    Backs the portal's admin usage-view dropdown. Only ever lists people
    with broker activity -- never a full Keycloak user directory.
    """
    store: UsageStore | None = getattr(request.app.state, "usage_store", None)
    if store is None:
        return UsageSubjectsResponse(subjects=[])

    subjects = await store.list_subjects(days)
    principal_cache = getattr(request.app.state, "principal_cache", None)

    resolved: list[UsageSubject] = []
    for subject in subjects:
        unixname: str | None = None
        email = ""
        if principal_cache is not None:
            try:
                attrs = await principal_cache.get(subject)
                unixname = attrs.unixname
                email = attrs.email
            except PrincipalUnavailableError:
                pass  # unresolvable subject (e.g. deleted user) -- fall back to bare subject
        resolved.append(UsageSubject(subject=subject, unixname=unixname, email=email))

    return UsageSubjectsResponse(subjects=resolved)
```

Add imports: `require_admin` from `identity`, `PrincipalUnavailableError`
from `principal_cache`.

**Note (open item from the design doc, now resolved):** unresolvable
subjects are included with `unixname=None, email=""` rather than omitted —
an admin should still be able to see *that* a deleted-user subject has usage,
even without a friendly label. This route must be registered on the
`usage.router` **before** the plan writes any `/{something}` catch-all path
on this router — check there isn't one already; if there is, order matters
in FastAPI route registration.

**Step 4: Run test to verify it passes**

Run: `pixi run -e dev pytest broker/tests/test_usage_api.py -v`
Expected: PASS, full file.

**Step 5: Commit**

```bash
git add broker/src/af_mcp_broker/api/usage.py broker/tests/test_usage_api.py
git commit -m "$(cat <<'EOF'
feat(broker): add admin-only GET /v1/usage/subjects

Resolves each subject with recorded usage to unixname/email via the
existing principal cache, backing the portal's admin usage-view dropdown.

Assisted-by: Claude (Anthropic)
EOF
)"
```

---

### Task B5: Portal — admin usage dropdown

**Files:**
- Modify: `portal/src/lib/api.ts`
- Modify: `portal/src/components/AdminPage.vue`
- Test: `portal/src/components/__tests__/AdminPage.test.ts`

**Step 1** — read `portal/src/components/UsagePage.vue` and `UsageCard.vue`
in full to see how they're structured (props in, or self-fetching?) — the
design calls for reusing these components with a different data source, not
re-implementing usage rendering.

**Step 2: Write the failing test** — extend `AdminPage.test.ts`:

```typescript
it('fetches subjects and lets the admin pick one', async () => {
  // mock fetchUsageSubjects / fetchUsage from '../../lib/api' the same way
  // UsagePage.test.ts already mocks fetchUsage -- match that file's mocking
  // style exactly (likely vi.mock('../../lib/api', ...)).
  const wrapper = mount(AdminPage);
  await flushPromises();
  expect(wrapper.find('select').exists()).toBe(true);
});
```

**Step 3: Run test to verify it fails**

Expected: FAIL — no `<select>` in the current shell.

**Step 4: Write minimal implementation**

In `portal/src/lib/api.ts`, add:

```typescript
export interface UsageSubject {
  subject: string;
  unixname: string | null;
  email: string;
}

export interface UsageSubjectsResponse {
  subjects: UsageSubject[];
}

export async function fetchUsageSubjects(days = 30): Promise<UsageSubjectsResponse> {
  // Mirror fetchUsage's exact request/error-handling shape (lines ~697-699) --
  // read it before writing this.
}
```

Update `fetchUsage` (or add a sibling) so it can pass `subject=` through —
check whether adding an optional `subject` parameter to the existing
`fetchUsage(days, subject?)` is cleaner than a second function; prefer
extending the existing one since `UsagePage.vue` and the new admin view both
want the same response shape.

In `AdminPage.vue`:

```vue
<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { fetchUsage, fetchUsageSubjects, type UsageResponse, type UsageSubject } from '../lib/api';
import UsagePage from './UsagePage.vue';

const subjects = ref<UsageSubject[]>([]);
const selected = ref<string>('');
const usage = ref<UsageResponse | null>(null);

onMounted(async () => {
  subjects.value = (await fetchUsageSubjects()).subjects;
});

async function onSelect(): Promise<void> {
  if (!selected.value) {
    usage.value = null;
    return;
  }
  usage.value = await fetchUsage(30, selected.value);
}
</script>

<template>
  <section class="af-panel">
    <h1>Admin</h1>
    <label>
      View usage for
      <select v-model="selected" @change="onSelect">
        <option value="">Select a user…</option>
        <option v-for="s in subjects" :key="s.subject" :value="s.subject">
          {{ s.unixname ?? s.email ?? s.subject }}
        </option>
      </select>
    </label>
    <UsagePage v-if="usage" :usage="usage" />
  </section>
</template>
```

This assumes `UsagePage.vue` accepts its data as a prop — if it instead
self-fetches internally (common in this codebase's page-level components,
per `UsagePage.vue`'s name and the earlier read in Step 1), this needs a
small refactor: extract `UsagePage.vue`'s rendering into a presentational
sub-component (or add an optional `usage` prop that, when provided, skips
its internal fetch) so both the self-service Usage page and this admin view
render through the same markup, per the design doc's "no new
usage-rendering code" goal. Make this call after reading the real file, not
before.

**Step 5: Run test to verify it passes**

Expected: PASS.

**Step 6: Manually verify in the browser** (same two-terminal setup as Task
A6) — as an admin dev-bypass principal, confirm the dropdown lists at least
one seeded-usage subject and selecting it renders that subject's usage.

**Step 7: Commit**

```bash
git add portal/src/lib/api.ts portal/src/components/AdminPage.vue portal/src/components/UsagePage.vue portal/src/components/__tests__/AdminPage.test.ts
git commit -m "$(cat <<'EOF'
feat(portal): admin usage-for-other-users dropdown

Reuses UsagePage's existing rendering, fed by a different data source
(GET /v1/usage/subjects, then GET /v1/usage?subject=) rather than
duplicating usage-rendering markup.

Assisted-by: Claude (Anthropic)
EOF
)"
```

---

# Part C — Maintenance mode

### Task C1: Settings for the maintenance-mode backend

**Files:**
- Modify: `broker/src/af_mcp_broker/config.py`
- Test: `broker/tests/test_config.py`

**Step 1: Write the failing tests** — mirror the `usage_store_backend`
tests exactly:

```python
# ---------------------------------------------------------------------------
# Maintenance mode backend (2026-08-28 admin capabilities design)
# ---------------------------------------------------------------------------


def test_maintenance_mode_backend_defaults_to_in_memory():
    settings = Settings()
    assert settings.maintenance_mode_backend == "in_memory"
    assert settings.maintenance_mode_postgres_dsn is None


def test_maintenance_mode_postgres_ok_when_own_dsn_set():
    Settings(
        maintenance_mode_backend="postgres",
        maintenance_mode_postgres_dsn="postgresql://broker:pw@pg.example/maint",
    )  # must not raise


def test_maintenance_mode_postgres_falls_back_to_usage_dsn():
    settings = Settings(
        maintenance_mode_backend="postgres",
        usage_postgres_dsn="postgresql://broker:pw@pg.example/usage",
    )  # must not raise -- reuses usage_postgres_dsn
    assert (
        settings.maintenance_mode_effective_postgres_dsn.get_secret_value()
        == "postgresql://broker:pw@pg.example/usage"
    )


def test_maintenance_mode_postgres_raises_when_no_dsn_available():
    with pytest.raises(ValueError, match="maintenance_mode_postgres_dsn"):
        Settings(maintenance_mode_backend="postgres")


def test_maintenance_mode_rejects_unknown_backend():
    with pytest.raises(ValueError, match="maintenance_mode_backend"):
        Settings(maintenance_mode_backend="mysql")
```

**Step 2: Run test to verify it fails**

Run: `pixi run -e dev pytest broker/tests/test_config.py -k maintenance_mode -v`
Expected: FAIL — field doesn't exist.

**Step 3: Write minimal implementation** — add to `config.py`, near
`usage_store_backend`/`usage_postgres_dsn`:

```python
    # Which MaintenanceModeStore implementation (maintenance.py) holds the
    # broker's maintenance-mode flag -- must be visible to every replica
    # consistently, following the same in_memory/vault/postgres selection
    # shape as usage_store_backend/token_registry_backend above (2026-08-28
    # admin capabilities design). "in_memory" is the single-replica/local-dev
    # default; a startup check below warns (never fails) when it's selected
    # alongside more than one replica, since maintenance mode then won't
    # propagate across pods.
    maintenance_mode_backend: Literal["in_memory", "vault", "postgres"] = "in_memory"

    # asyncpg-compatible DSN for the postgres maintenance-mode store. Falls
    # back to usage_postgres_dsn when unset (maintenance_mode_effective_
    # postgres_dsn below) -- a facility already running Postgres for usage
    # reuses it with no new secret, but isn't forced to couple the two.
    maintenance_mode_postgres_dsn: SecretStr | None = None

    # KV-v2 path prefix for the persisted maintenance-mode record, distinct
    # from every other Vault-backed store's prefix so they never collide
    # under the same kv_mount.
    maintenance_mode_kv_path_prefix: str = "mcp/maintenance-mode"
```

Add the `effective` property near `broker_token_effective_issuer`:

```python
    @property
    def maintenance_mode_effective_postgres_dsn(self) -> SecretStr | None:
        """``maintenance_mode_postgres_dsn`` if set, else ``usage_postgres_dsn``.

        Computed at read time (like ``broker_token_effective_issuer``) so it
        always reflects the current value of either field.
        """
        return self.maintenance_mode_postgres_dsn or self.usage_postgres_dsn
```

Add the validator near `_validate_usage_store_config`:

```python
    @model_validator(mode="after")
    def _validate_maintenance_mode_config(self) -> Settings:
        """Fail startup loudly when the postgres maintenance-mode backend is selected without a DSN (its own, or usage_postgres_dsn as a fallback) -- same rationale as ``_validate_usage_store_config``."""
        if self.maintenance_mode_backend != "postgres":
            return self
        dsn = self.maintenance_mode_effective_postgres_dsn
        if dsn is None or not dsn.get_secret_value():
            log.error(
                "maintenance_mode_config_invalid",
                reason=(
                    "maintenance_mode_postgres_dsn and usage_postgres_dsn "
                    "are both empty but maintenance_mode_backend is "
                    "'postgres'"
                ),
            )
            raise ValueError(
                "maintenance_mode_postgres_dsn (MAINTENANCE_MODE_POSTGRES_DSN) "
                "or usage_postgres_dsn (USAGE_POSTGRES_DSN) must be set when "
                "maintenance_mode_backend is 'postgres'."
            )
        return self
```

**Step 4: Run test to verify it passes**

Run: `pixi run -e dev pytest broker/tests/test_config.py -k maintenance_mode -v`
Expected: PASS (5 tests)

**Step 5: Commit**

```bash
git add broker/src/af_mcp_broker/config.py broker/tests/test_config.py
git commit -m "$(cat <<'EOF'
feat(broker): add maintenance-mode backend settings

in_memory/vault/postgres selection, mirroring usage_store_backend's
shape. The postgres option falls back to usage_postgres_dsn when its
own DSN is unset, so a facility already running Postgres for usage can
reuse it with no new secret.

Assisted-by: Claude (Anthropic)
EOF
)"
```

---

### Task C2: `MaintenanceModeStore` ABC + in-memory backend

**Files:**
- Create: `broker/src/af_mcp_broker/maintenance.py`
- Test: create `broker/tests/test_maintenance.py`

**Step 1: Write the failing test**

```python
"""Tests for maintenance.py -- the maintenance-mode store (2026-08-28 admin capabilities design)."""

from __future__ import annotations

import time

from af_mcp_broker.maintenance import InMemoryMaintenanceModeStore, MaintenanceState


async def test_default_state_is_disabled():
    store = InMemoryMaintenanceModeStore()
    state = await store.get()
    assert state == MaintenanceState(
        enabled=False, reason=None, enabled_by=None, enabled_at=None
    )


async def test_set_then_get_roundtrips():
    store = InMemoryMaintenanceModeStore()
    written = MaintenanceState(
        enabled=True, reason="upgrading", enabled_by="admin-sub", enabled_at=time.time()
    )
    await store.set(written)
    assert await store.get() == written
```

**Step 2: Run test to verify it fails**

Run: `pixi run -e dev pytest broker/tests/test_maintenance.py -v`
Expected: FAIL — `ModuleNotFoundError`.

**Step 3: Write minimal implementation** — create
`broker/src/af_mcp_broker/maintenance.py`:

```python
"""Broker-wide maintenance mode (2026-08-28 admin capabilities design).

Toggling maintenance mode must be visible to every broker replica
consistently, so this follows the same ABC-plus-selectable-backend shape as
``token_registry.TokenRegistryBackend``/``usage.UsageStore``: an admin flips
the flag via ``POST /v1/admin/maintenance``, and every replica's ``/v1`` and
``/mcp`` request paths consult the same store before admitting a
non-admin caller (``authorization.base.is_admin`` always bypasses the gate).

``MaintenanceModeStore`` has ``start()``/``aclose()`` like ``UsageStore``
(not the simpler get/put-only shape of ``PrincipalCacheBackend``/
``TokenRegistryBackend``) because the postgres backend needs its own asyncpg
connection pool lifecycle; the in-memory and Vault backends' start/aclose are
no-ops, matching ``InMemoryUsageStore``'s asymmetry with
``PostgresUsageStore``.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from af_mcp_broker.vault_kv import VaultKV


@dataclass(frozen=True)
class MaintenanceState:
    """The broker's maintenance-mode flag and who set it."""

    enabled: bool
    reason: str | None
    enabled_by: str | None  # admin subject
    enabled_at: float | None  # time.time()


_DISABLED = MaintenanceState(enabled=False, reason=None, enabled_by=None, enabled_at=None)


class MaintenanceModeStore(abc.ABC):
    """Durable storage for the broker's single maintenance-mode record."""

    @abc.abstractmethod
    async def start(self) -> None:
        """Acquire whatever the backend needs (connections, schema)."""

    @abc.abstractmethod
    async def aclose(self) -> None:
        """Release the backend's resources."""

    @abc.abstractmethod
    async def get(self) -> MaintenanceState:
        """Return the current maintenance state -- disabled if never set."""

    @abc.abstractmethod
    async def set(self, state: MaintenanceState) -> None:
        """Overwrite the current maintenance state."""


class InMemoryMaintenanceModeStore(MaintenanceModeStore):
    """Process-local, single-replica store -- the dev/local default."""

    def __init__(self) -> None:
        self._state: MaintenanceState = _DISABLED

    async def start(self) -> None:
        """Nothing to acquire."""

    async def aclose(self) -> None:
        """Nothing to release."""

    async def get(self) -> MaintenanceState:
        return self._state

    async def set(self, state: MaintenanceState) -> None:
        self._state = state
```

**Step 4: Run test to verify it passes**

Run: `pixi run -e dev pytest broker/tests/test_maintenance.py -v`
Expected: PASS (2 tests)

**Step 5: Commit**

```bash
git add broker/src/af_mcp_broker/maintenance.py broker/tests/test_maintenance.py
git commit -m "$(cat <<'EOF'
feat(broker): add MaintenanceModeStore ABC + in-memory backend

Assisted-by: Claude (Anthropic)
EOF
)"
```

---

### Task C3: `VaultMaintenanceModeStore`

**Files:**
- Modify: `broker/src/af_mcp_broker/maintenance.py`
- Test: `broker/tests/test_maintenance.py`

**Step 1: Write the failing test** — copy `test_token_registry.py`'s
`_FakeRegistryVault`/`sa_token_path` fixture pattern (or better: check
whether it's worth extracting that fake into a shared test helper module
first, since this is now its second use outside x509 — if a shared fake
already exists for `test_x509_vault.py` too, reuse it instead of copying a
third time; grep `broker/tests/` for `_FakeRegistryVault`/`_FakeVault` before
deciding):

```python
import httpx
import pytest

from af_mcp_broker.maintenance import VaultMaintenanceModeStore
from af_mcp_broker.vault_kv import VaultKV

# ... reuse or adapt the fake Vault handler from test_token_registry.py ...


@pytest.fixture
def vault_kv(sa_token_path) -> VaultKV:
    fake = _FakeVault()
    return VaultKV(
        addr="https://vault.invalid",
        auth_mount="kubernetes",
        auth_role="af-mcp-broker",
        kv_mount="secret",
        sa_token_path=str(sa_token_path),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(fake.handle)),
    )


async def test_vault_default_state_is_disabled(vault_kv):
    store = VaultMaintenanceModeStore(vault_kv=vault_kv, kv_path_prefix="mcp/maintenance-mode")
    assert (await store.get()).enabled is False


async def test_vault_set_then_get_roundtrips(vault_kv):
    store = VaultMaintenanceModeStore(vault_kv=vault_kv, kv_path_prefix="mcp/maintenance-mode")
    state = MaintenanceState(enabled=True, reason="r", enabled_by="admin", enabled_at=1.0)
    await store.set(state)
    assert await store.get() == state
```

**Step 2: Run test to verify it fails**

Run: `pixi run -e dev pytest broker/tests/test_maintenance.py -k vault -v`
Expected: FAIL — `ImportError`.

**Step 3: Write minimal implementation** — add to `maintenance.py`:

```python
_KV_KEY = "state"


def _state_to_fields(state: MaintenanceState) -> dict[str, object]:
    return {
        "enabled": state.enabled,
        "reason": state.reason,
        "enabled_by": state.enabled_by,
        "enabled_at": state.enabled_at,
    }


def _state_from_fields(fields: dict[str, object]) -> MaintenanceState:
    return MaintenanceState(
        enabled=bool(fields.get("enabled", False)),
        reason=fields.get("reason"),  # type: ignore[arg-type]
        enabled_by=fields.get("enabled_by"),  # type: ignore[arg-type]
        enabled_at=fields.get("enabled_at"),  # type: ignore[arg-type]
    )


class VaultMaintenanceModeStore(MaintenanceModeStore):
    """``MaintenanceModeStore`` backed by Vault/OpenBao KV-v2, one record at ``{kv_path_prefix}/state`` -- HA-safe across replicas."""

    def __init__(self, *, vault_kv: VaultKV, kv_path_prefix: str) -> None:
        self._vault_kv = vault_kv
        self._path = f"{kv_path_prefix.strip('/')}/{_KV_KEY}"

    async def start(self) -> None:
        """Nothing to acquire -- vault_kv is already authenticated by app.py's lifespan."""

    async def aclose(self) -> None:
        """Nothing to release."""

    async def get(self) -> MaintenanceState:
        current = await self._vault_kv.get(self._path)
        if current is None:
            return _DISABLED
        data, _version = current
        return _state_from_fields(data)

    async def set(self, state: MaintenanceState) -> None:
        current = await self._vault_kv.get(self._path)
        version = current[1] if current is not None else None
        await self._vault_kv.write_cas(self._path, _state_to_fields(state), version)
```

Note: unlike `VaultPrincipalCacheBackend`'s `put()`, this has no CAS-retry
loop — a lost race here (two admins toggling simultaneously) just means the
loser's write raises `CasConflict` once, which the admin API surfaces as a
502/409 asking them to retry, rather than silently retrying a state-changing
admin action. If you want the retry loop for parity with
`VaultPrincipalCacheBackend`, ask before adding it — it's a judgment call,
not implied by the design doc.

**Step 4: Run test to verify it passes**

Run: `pixi run -e dev pytest broker/tests/test_maintenance.py -v`
Expected: PASS, full file.

**Step 5: Commit**

```bash
git add broker/src/af_mcp_broker/maintenance.py broker/tests/test_maintenance.py
git commit -m "$(cat <<'EOF'
feat(broker): add VaultMaintenanceModeStore

Assisted-by: Claude (Anthropic)
EOF
)"
```

---

### Task C4: `PostgresMaintenanceModeStore`

**Files:**
- Modify: `broker/src/af_mcp_broker/maintenance.py`
- Test: create `broker/tests/test_maintenance_postgres.py`

**Step 1: Write the failing test** — reuse the `postgres_dsn` fixture moved
to `conftest.py` in Task B2:

```python
"""Tests for PostgresMaintenanceModeStore against a REAL ephemeral postgres (no mocks -- see conftest.py's postgres_dsn fixture)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from af_mcp_broker.maintenance import MaintenanceState, PostgresMaintenanceModeStore

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


@pytest.fixture
async def store(postgres_dsn: str) -> AsyncIterator[PostgresMaintenanceModeStore]:
    s = PostgresMaintenanceModeStore(postgres_dsn)
    await s.start()
    yield s
    await s.aclose()


async def test_default_state_is_disabled(store: PostgresMaintenanceModeStore) -> None:
    state = await store.get()
    assert state.enabled is False


async def test_set_then_get_roundtrips(store: PostgresMaintenanceModeStore) -> None:
    written = MaintenanceState(
        enabled=True, reason="upgrading", enabled_by="admin-sub", enabled_at=1234.0
    )
    await store.set(written)
    assert await store.get() == written


async def test_start_ddl_is_idempotent(postgres_dsn: str) -> None:
    first = PostgresMaintenanceModeStore(postgres_dsn)
    await first.start()
    second = PostgresMaintenanceModeStore(postgres_dsn)
    await second.start()  # must not raise
    await first.aclose()
    await second.aclose()
```

**Step 2: Run test to verify it fails**

Run: `pixi run -e dev pytest broker/tests/test_maintenance_postgres.py -v`
Expected: FAIL — `ImportError`.

**Step 3: Write minimal implementation** — add to `maintenance.py`:

```python
import asyncpg  # type: ignore[import-untyped]

# Idempotent DDL, single-row table (id is always 1) -- mirrors usage/postgres.py's
# CREATE TABLE IF NOT EXISTS shape; one table does not justify a migration
# framework here either.
_DDL = """
CREATE TABLE IF NOT EXISTS af_mcp_maintenance_mode (
    id SMALLINT PRIMARY KEY DEFAULT 1,
    enabled BOOLEAN NOT NULL,
    reason TEXT,
    enabled_by TEXT,
    enabled_at DOUBLE PRECISION,
    CONSTRAINT single_row CHECK (id = 1)
);
"""

_UPSERT = """
INSERT INTO af_mcp_maintenance_mode (id, enabled, reason, enabled_by, enabled_at)
VALUES (1, $1, $2, $3, $4)
ON CONFLICT (id) DO UPDATE SET
    enabled = EXCLUDED.enabled,
    reason = EXCLUDED.reason,
    enabled_by = EXCLUDED.enabled_by,
    enabled_at = EXCLUDED.enabled_at
"""

_SELECT = "SELECT enabled, reason, enabled_by, enabled_at FROM af_mcp_maintenance_mode WHERE id = 1"


class PostgresMaintenanceModeStore(MaintenanceModeStore):
    """``MaintenanceModeStore`` backed by a single-row Postgres table (asyncpg)."""

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._pool: asyncpg.Pool | None = None

    async def start(self) -> None:
        self._pool = await asyncpg.create_pool(self._dsn)
        async with self._pool.acquire() as conn:
            await conn.execute(_DDL)

    async def aclose(self) -> None:
        if self._pool is None:
            return
        await self._pool.close()
        self._pool = None

    def _require_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError("PostgresMaintenanceModeStore used before start()")
        return self._pool

    async def get(self) -> MaintenanceState:
        row = await self._require_pool().fetchrow(_SELECT)
        if row is None:
            return _DISABLED
        return MaintenanceState(
            enabled=row["enabled"],
            reason=row["reason"],
            enabled_by=row["enabled_by"],
            enabled_at=row["enabled_at"],
        )

    async def set(self, state: MaintenanceState) -> None:
        await self._require_pool().execute(
            _UPSERT, state.enabled, state.reason, state.enabled_by, state.enabled_at
        )
```

**Step 4: Run test to verify it passes**

Run: `pixi run -e dev pytest broker/tests/test_maintenance_postgres.py -v`
Expected: PASS, full file.

**Step 5: Commit**

```bash
git add broker/src/af_mcp_broker/maintenance.py broker/tests/test_maintenance_postgres.py
git commit -m "$(cat <<'EOF'
feat(broker): add PostgresMaintenanceModeStore

Single-row table, upsert on set() -- can reuse the same DSN as the
postgres usage store (Settings.maintenance_mode_effective_postgres_dsn).

Assisted-by: Claude (Anthropic)
EOF
)"
```

---

### Task C5: `check_not_maintenance()` gate helper

**Files:**
- Modify: `broker/src/af_mcp_broker/maintenance.py`
- Test: `broker/tests/test_maintenance.py`

**Step 1: Write the failing test**

```python
from af_mcp_broker.config import Settings
from af_mcp_broker.maintenance import check_not_maintenance


async def test_admin_bypasses_maintenance(make_principal):
    settings = Settings(admin_group="af-admins")
    principal = make_principal(groups=["af-admins"])
    store = InMemoryMaintenanceModeStore()
    await store.set(MaintenanceState(enabled=True, reason="r", enabled_by="x", enabled_at=1.0))

    await check_not_maintenance(principal, settings, store)  # must not raise


async def test_non_admin_blocked_with_reason(make_principal):
    settings = Settings(admin_group="af-admins")
    principal = make_principal(groups=["atlas"])
    store = InMemoryMaintenanceModeStore()
    await store.set(MaintenanceState(enabled=True, reason="upgrading", enabled_by="x", enabled_at=1.0))

    with pytest.raises(HTTPException) as exc_info:
        await check_not_maintenance(principal, settings, store)
    assert exc_info.value.status_code == 503
    assert "upgrading" in str(exc_info.value.detail)


async def test_disabled_maintenance_never_raises(make_principal):
    settings = Settings(admin_group="af-admins")
    principal = make_principal(groups=["atlas"])
    store = InMemoryMaintenanceModeStore()

    await check_not_maintenance(principal, settings, store)  # must not raise


async def test_no_store_configured_never_raises(make_principal):
    settings = Settings(admin_group="af-admins")
    principal = make_principal(groups=["atlas"])

    await check_not_maintenance(principal, settings, None)  # must not raise
```

**Step 2: Run test to verify it fails**

Run: `pixi run -e dev pytest broker/tests/test_maintenance.py -k check_not_maintenance -v`
Expected: FAIL — `ImportError`.

**Step 3: Write minimal implementation** — add to `maintenance.py`:

```python
from fastapi import HTTPException, status

from af_mcp_broker.authorization.base import is_admin

if TYPE_CHECKING:
    from af_mcp_broker.config import Settings
    from af_mcp_broker.identity import Principal


async def check_not_maintenance(
    principal: Principal,
    settings: Settings,
    store: MaintenanceModeStore | None,
) -> None:
    """Raise HTTPException(503) when maintenance mode is on and *principal* is not an admin.

    Called from both /v1 (require_not_in_maintenance, identity.py) and /mcp
    (AsgiAuthMiddleware, mcp/middleware/identity_mw.py) right after a
    Principal is resolved (JWT or PAT) -- one gate, two call sites, so both
    credential types and both surfaces are covered uniformly. A None *store*
    (maintenance mode unconfigured -- unreachable in a properly started app,
    but matches the getattr-default-None pattern every other optional
    app.state lookup in this codebase uses) never blocks anyone.
    """
    if store is None:
        return
    if is_admin(principal, settings):
        return
    state = await store.get()
    if not state.enabled:
        return
    detail = "The broker is in maintenance mode."
    if state.reason:
        detail = f"{detail} Reason: {state.reason}"
    raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=detail)
```

**Step 4: Run test to verify it passes**

Run: `pixi run -e dev pytest broker/tests/test_maintenance.py -v`
Expected: PASS, full file.

**Step 5: Commit**

```bash
git add broker/src/af_mcp_broker/maintenance.py broker/tests/test_maintenance.py
git commit -m "$(cat <<'EOF'
feat(broker): add check_not_maintenance() gate helper

One gate, two call sites (/v1 and /mcp) -- see the enforcement tasks
that wire it in next.

Assisted-by: Claude (Anthropic)
EOF
)"
```

---

### Task C6: `require_not_in_maintenance` dependency + router wiring (`/v1`)

**Files:**
- Modify: `broker/src/af_mcp_broker/identity.py`
- Modify: `broker/src/af_mcp_broker/api/router.py`
- Test: create `broker/tests/test_maintenance_v1_enforcement.py`

**Step 1: Write the failing test** — use `app_client_factory`:

```python
"""Integration tests for maintenance-mode enforcement on /v1 (2026-08-28 admin capabilities design)."""

from __future__ import annotations

import pytest

from af_mcp_broker.maintenance import InMemoryMaintenanceModeStore, MaintenanceState


def test_non_admin_blocked_when_maintenance_enabled(app_client_factory, monkeypatch):
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")
    with app_client_factory() as (client, state):
        client.app.state.maintenance_mode_store = InMemoryMaintenanceModeStore()
        import asyncio

        asyncio.run(
            client.app.state.maintenance_mode_store.set(
                MaintenanceState(enabled=True, reason="r", enabled_by="a", enabled_at=1.0)
            )
        )
        resp = client.get("/v1/identities")
        assert resp.status_code == 503


def test_admin_not_blocked_when_maintenance_enabled(app_client_factory, monkeypatch, make_principal):
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")
    with app_client_factory() as (client, state):
        state["principal"] = make_principal(groups=["af-admins"])
        client.app.state.maintenance_mode_store = InMemoryMaintenanceModeStore()
        import asyncio

        asyncio.run(
            client.app.state.maintenance_mode_store.set(
                MaintenanceState(enabled=True, reason="r", enabled_by="a", enabled_at=1.0)
            )
        )
        resp = client.get("/v1/identities")
        assert resp.status_code == 200


def test_health_probe_never_blocked(app_client_factory):
    with app_client_factory() as (client, _state):
        client.app.state.maintenance_mode_store = InMemoryMaintenanceModeStore()
        import asyncio

        asyncio.run(
            client.app.state.maintenance_mode_store.set(
                MaintenanceState(enabled=True, reason="r", enabled_by="a", enabled_at=1.0)
            )
        )
        resp = client.get("/v1/healthz")  # confirm the real health path first
        assert resp.status_code == 200
```

Check `api/health.py` for the real route paths (`/healthz`/`/readyz`) before
finalizing that last test.

**Step 2: Run test to verify it fails**

Run: `pixi run -e dev pytest broker/tests/test_maintenance_v1_enforcement.py -v`
Expected: FAIL — nothing blocks anyone yet (503 tests fail with 200).

**Step 3: Write minimal implementation**

In `identity.py`, add after `keycloak_dependency`:

```python
async def require_not_in_maintenance(
    request: Request,
    principal: Annotated[Principal, Depends(keycloak_dependency)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Principal:
    """FastAPI dependency: 503s when maintenance mode is on and the caller isn't an admin.

    A separate dependency from keycloak_dependency (not folded into it)
    because GET /v1/admin/maintenance must stay reachable by every caller
    (so the portal can show a maintenance banner to non-admins too) and
    /v1's health probes must never be gated (Kubernetes would otherwise
    restart pods during a deliberate maintenance window) -- see
    api/router.py for exactly which routers this is applied to.
    """
    store = getattr(request.app.state, "maintenance_mode_store", None)
    await check_not_maintenance(principal, settings, store)
    return principal
```

Add `from af_mcp_broker.maintenance import check_not_maintenance` to the
imports (verify no circular import: `maintenance.py` imports `Principal`/
`Settings` only under `TYPE_CHECKING`, so this is safe).

In `api/router.py`, apply the dependency to every router except `health` and
the not-yet-created `admin` router:

```python
from fastapi import APIRouter, Depends

from af_mcp_broker.api import (
    catalog_tools,
    credentials,
    health,
    identities,
    mcp_oauth,
    oauth21,
    permissions,
    tokens,
    usage,
)
from af_mcp_broker.identity import require_not_in_maintenance

router = APIRouter(prefix="/v1")

# Health probes must never be gated by maintenance mode -- Kubernetes
# liveness/readiness checks have to keep passing during a deliberate
# maintenance window, or the platform restarts pods exactly when it
# shouldn't.
router.include_router(health.router)

_maintenance_gated = [Depends(require_not_in_maintenance)]
router.include_router(identities.router, dependencies=_maintenance_gated)
router.include_router(permissions.router, dependencies=_maintenance_gated)
router.include_router(catalog_tools.router, dependencies=_maintenance_gated)
router.include_router(credentials.router, dependencies=_maintenance_gated)
router.include_router(oauth21.router, dependencies=_maintenance_gated)
router.include_router(tokens.router, dependencies=_maintenance_gated)
router.include_router(mcp_oauth.router, dependencies=_maintenance_gated)
router.include_router(usage.router, dependencies=_maintenance_gated)
```

(The new `admin.router` is added in Task C9, deliberately without
`_maintenance_gated` — its `GET` status route must stay reachable during
maintenance, and its `POST` route is already `require_admin`-gated, which
`is_admin` inside `check_not_maintenance` would bypass anyway, but keeping
it off this list avoids depending on that bypass for the one route where
*visibility during an outage* is the actual point.)

**Step 4: Run test to verify it passes**

Run: `pixi run -e dev pytest broker/tests/test_maintenance_v1_enforcement.py -v`
Expected: PASS (3 tests)

Then run the FULL broker suite once to catch any route whose existing tests
never set `app.state.maintenance_mode_store` and now behaves differently:

Run: `pixi run -e dev pytest broker/ -v`
Expected: PASS. Because `require_not_in_maintenance` uses
`getattr(..., None)` and `check_not_maintenance` treats a `None` store as
"never block," every existing test that doesn't touch maintenance mode at
all should be unaffected — investigate immediately if anything else broke.

**Step 5: Commit**

```bash
git add broker/src/af_mcp_broker/identity.py broker/src/af_mcp_broker/api/router.py broker/tests/test_maintenance_v1_enforcement.py
git commit -m "$(cat <<'EOF'
feat(broker): enforce maintenance mode on /v1

Applied per-router (dependencies=) rather than folded into
keycloak_dependency, so health probes and the maintenance-status
read stay reachable during a maintenance window.

Assisted-by: Claude (Anthropic)
EOF
)"
```

---

### Task C7: Enforce maintenance mode on `/mcp` (JWT and PAT)

**Files:**
- Modify: `broker/src/af_mcp_broker/mcp/middleware/identity_mw.py`
- Modify: `broker/src/af_mcp_broker/mcp/aggregator.py`
- Test: find or create `broker/tests/test_mcp_identity_middleware.py` (grep
  for existing tests of `AsgiAuthMiddleware`/`IdentityMiddleware` first —
  there's almost certainly a file already covering PAT-vs-JWT dispatch on
  `/mcp` that this should extend).

**Step 1: Write the failing test** — extend the existing middleware test
file (read it first to match its app-building helper exactly):

```python
async def test_mcp_blocks_non_admin_during_maintenance(...):
    # build the test aggregator app the same way the existing tests do,
    # with a maintenance_mode_store set on the IdentityMiddleware and
    # enabled=True, caller not in admin_group
    ...
    assert response.status_code == 503


async def test_mcp_allows_admin_during_maintenance(...):
    ...
    assert response.status_code != 503
```

**Step 2: Run test to verify it fails**

Run: `pixi run -e dev pytest <that file> -k maintenance -v`
Expected: FAIL.

**Step 3: Write minimal implementation**

In `identity_mw.py`'s `IdentityMiddleware.__init__`, add a
`maintenance_mode_store` parameter (mirroring how `pat_backend`/
`principal_cache` are already optional constructor params kept on `self`):

```python
    def __init__(
        self,
        settings: Settings,
        revoked_jti_cache: RevokedJtiCache | None = None,
        pat_backend: TokenRegistryBackend | None = None,
        principal_cache: PrincipalCache | None = None,
        maintenance_mode_store: MaintenanceModeStore | None = None,
    ) -> None:
        ...
        self.maintenance_mode_store = maintenance_mode_store
```

Add the import: `from af_mcp_broker.maintenance import (MaintenanceModeStore,
check_not_maintenance)` (only `MaintenanceModeStore` needs to be real at
type-check time — put both under `TYPE_CHECKING` if only used in
annotations, but `check_not_maintenance` is called at runtime in
`AsgiAuthMiddleware` below, so import it unconditionally).

In `AsgiAuthMiddleware.__call__`, right after the `principal` variable is
fully resolved in both branches (dev-bypass, JWT, PAT) and right before
`scope.setdefault("state", {})`:

```python
        settings = self._identity_mw.settings
        ...
        maintenance_mode_store = self._identity_mw.maintenance_mode_store
        try:
            await check_not_maintenance(principal, settings, maintenance_mode_store)
        except HTTPException as exc:
            await _send_error(scope, receive, send, exc.status_code, str(exc.detail))
            return

        scope.setdefault("state", {})
        scope["state"]["principal"] = principal
        await self.app(scope, receive, send)
```

In `mcp/aggregator.py`, thread the new parameter through `build_aggregator`
and `populate_aggregator` (both already take the same set of optional
params — add `maintenance_mode_store: MaintenanceModeStore | None = None` to
both signatures, pass it into `IdentityMiddleware(...)` in
`build_aggregator`, and assign `identity_mw.maintenance_mode_store =
maintenance_mode_store` in `populate_aggregator`, in both cases right next to
the existing `principal_cache` wiring).

**Step 4: Run test to verify it passes**

Run: `pixi run -e dev pytest <that file> -v`
Expected: PASS, full file.

Run the full suite: `pixi run -e dev pytest broker/ -v`
Expected: PASS (defaults are `None` everywhere they're not explicitly
passed, so every existing `build_aggregator(...)`/`populate_aggregator(...)`
call site not yet updated for C8 continues to behave exactly as before).

**Step 5: Commit**

```bash
git add broker/src/af_mcp_broker/mcp/middleware/identity_mw.py broker/src/af_mcp_broker/mcp/aggregator.py broker/tests/<that file>
git commit -m "$(cat <<'EOF'
feat(broker): enforce maintenance mode on /mcp

One check_not_maintenance() call in AsgiAuthMiddleware, right after
principal resolution converges for both JWT and PAT bearers -- covers
both credential types with no second code path.

Assisted-by: Claude (Anthropic)
EOF
)"
```

---

### Task C8: Wire the real store into `app.py`'s lifespan

**Files:**
- Modify: `broker/src/af_mcp_broker/app.py`
- Test: create/extend `broker/tests/test_app_lifespan.py` (check if a file
  like this already exists covering the `unreachable_permissions`/
  `broker_token_issuer` startup checks — likely does, given how many similar
  checks `app.py`'s lifespan has).

**Step 1: Write the failing test** — a startup-warning test mirroring the
existing `mcp_stateful_multi_replica` warning test (find it first — grep
`broker/tests/` for `mcp_stateful_multi_replica` or `caplog`):

```python
def test_warns_when_in_memory_maintenance_backend_with_multiple_replicas(
    monkeypatch, caplog
):
    monkeypatch.setenv("MCP_REPLICA_COUNT", "3")
    monkeypatch.setenv("MAINTENANCE_MODE_BACKEND", "in_memory")
    # boot the app the same way the existing replica-warning test does
    ...
    assert "maintenance_mode" in caplog.text  # match the real event name chosen below
```

**Step 2: Run test to verify it fails**

Expected: FAIL — no such warning is emitted yet.

**Step 3: Write minimal implementation** — in `app.py`'s `lifespan()`,
add a warning block right after the existing `mcp_stateful_multi_replica`
check (~line 206):

```python
    # --- Maintenance mode (2026-08-28 admin capabilities design): the
    # in-memory backend is process-local, so it won't propagate a toggle
    # across replicas -- warn (never fail) the same way the mcp_stateless_http
    # check above does, since a single-replica or local-dev deployment
    # legitimately wants this default with no extra infra.
    if (
        settings.maintenance_mode_backend == "in_memory"
        and settings.mcp_replica_count is not None
        and settings.mcp_replica_count > 1
    ):
        logger.warning(
            "maintenance_mode_in_memory_multi_replica",
            message=(
                "maintenance_mode_backend=in_memory with more than one "
                "broker replica: toggling maintenance mode via POST "
                "/v1/admin/maintenance only affects the replica that "
                "handled the request, so other replicas keep serving "
                "normally. Select maintenance_mode_backend=vault or "
                "=postgres for a toggle that's visible to every replica."
            ),
            replica_count=settings.mcp_replica_count,
        )
```

Then, near the `token_registry_backend`/`principal_cache` construction block
(~line 629-705), add the maintenance-mode store construction — after
`principal_cache` is built, reusing the shared `vault_kv` when relevant:

```python
    # --- Maintenance mode (2026-08-28 admin capabilities design): one
    # MaintenanceModeStore, selected the same in_memory/vault/postgres way
    # as usage_store_backend/token_registry_backend above.
    maintenance_mode_store: MaintenanceModeStore
    if settings.maintenance_mode_backend == "vault":
        assert vault_kv is not None  # guaranteed by the check below
        maintenance_mode_store = VaultMaintenanceModeStore(
            vault_kv=vault_kv,
            kv_path_prefix=settings.maintenance_mode_kv_path_prefix,
        )
    elif settings.maintenance_mode_backend == "postgres":
        dsn = settings.maintenance_mode_effective_postgres_dsn
        assert dsn is not None  # guaranteed by _validate_maintenance_mode_config
        maintenance_mode_store = PostgresMaintenanceModeStore(dsn.get_secret_value())
    else:
        maintenance_mode_store = InMemoryMaintenanceModeStore()
    await maintenance_mode_store.start()
```

This introduces a new case where `vault_kv` must be constructed: add
`settings.maintenance_mode_backend == "vault"` to the big `if` at line
326-331 that decides whether to build `vault_kv` at all:

```python
    if (
        settings.token_store_backend == "vault"
        or settings.token_registry_backend == "vault"
        or settings.principal_cache_backend == "vault"
        or settings.maintenance_mode_backend == "vault"
        or has_service_mode_x509_cfg
    ):
```

Assign onto state and populate_aggregator:

```python
    application.state.maintenance_mode_store = maintenance_mode_store
```

```python
    populate_aggregator(
        ...,
        maintenance_mode_store=maintenance_mode_store,
    )
```

And close it on shutdown, next to `await aclose_usage_store()`:

```python
    await maintenance_mode_store.aclose()
```

Add the imports:
`from af_mcp_broker.maintenance import (InMemoryMaintenanceModeStore,
MaintenanceModeStore, PostgresMaintenanceModeStore, VaultMaintenanceModeStore)`.

**Step 4: Run test to verify it passes**

Run the new test, then the full suite:

Run: `pixi run -e dev pytest broker/ -v`
Expected: PASS, no regressions — every other lifespan-constructed object's
tests are order-sensitive only around the `vault_kv` gating change, so pay
particular attention to any existing test that asserts `vault_kv is None`
under `maintenance_mode_backend`'s default (`in_memory`) — it should still
be `None` unless another backend already requires Vault.

**Step 5: Commit**

```bash
git add broker/src/af_mcp_broker/app.py broker/tests/test_app_lifespan.py
git commit -m "$(cat <<'EOF'
feat(broker): wire MaintenanceModeStore into app.py's lifespan

Constructs the configured backend, warns (never fails) when
in_memory is selected alongside more than one replica, and pushes
the store onto app.state and the aggregator.

Assisted-by: Claude (Anthropic)
EOF
)"
```

---

### Task C9: Admin API — `POST`/`GET /v1/admin/maintenance`

**Files:**
- Create: `broker/src/af_mcp_broker/api/admin.py`
- Modify: `broker/src/af_mcp_broker/api/router.py`
- Test: create `broker/tests/test_admin_api.py`

**Step 1: Write the failing test**

```python
"""Tests for the admin API -- POST/GET /v1/admin/maintenance (2026-08-28 admin capabilities design)."""

from __future__ import annotations

import pytest

from af_mcp_broker.maintenance import InMemoryMaintenanceModeStore


@pytest.fixture
def maintenance_client(app_client_factory, monkeypatch):
    monkeypatch.setenv("ADMIN_GROUP", "af-admins")
    with app_client_factory() as (client, state):
        client.app.state.maintenance_mode_store = InMemoryMaintenanceModeStore()
        yield client, state


def test_get_status_requires_no_auth_at_all(maintenance_client):
    client, _state = maintenance_client
    client.app.dependency_overrides.clear()  # simulate a genuinely unauthenticated caller
    resp = client.get("/v1/admin/maintenance")
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False


def test_post_requires_admin(maintenance_client):
    client, _state = maintenance_client
    resp = client.post("/v1/admin/maintenance", json={"enabled": True, "reason": "r"})
    assert resp.status_code == 403


def test_admin_can_enable_and_it_shows_up_on_get(maintenance_client, make_principal):
    client, state = maintenance_client
    state["principal"] = make_principal(groups=["af-admins"], subject="admin-sub")

    resp = client.post("/v1/admin/maintenance", json={"enabled": True, "reason": "upgrading"})
    assert resp.status_code == 200

    status_resp = client.get("/v1/admin/maintenance")
    body = status_resp.json()
    assert body["enabled"] is True
    assert body["reason"] == "upgrading"
    assert body["enabled_by"] == "admin-sub"
    assert body["enabled_at"] is not None
```

**Step 2: Run test to verify it fails**

Run: `pixi run -e dev pytest broker/tests/test_admin_api.py -v`
Expected: FAIL — 404s (route doesn't exist).

**Step 3: Write minimal implementation** — create
`broker/src/af_mcp_broker/api/admin.py`:

```python
"""GET/POST /v1/admin/maintenance -- broker-wide maintenance mode (2026-08-28 admin capabilities design).

GET carries no auth requirement at all (not even keycloak_dependency) so the
portal can show a maintenance banner to every visitor, including whoever is
currently blocked by it -- it must stay reachable precisely when everything
else is refusing traffic. POST requires admin-group membership
(require_admin); enabled_by/enabled_at are stamped server-side, never taken
from the request body, so an admin can't misattribute a toggle to someone
else.
"""

from __future__ import annotations

import time
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict

from af_mcp_broker.identity import Principal, require_admin
from af_mcp_broker.maintenance import MaintenanceModeStore, MaintenanceState

router = APIRouter(prefix="/admin", tags=["admin"])


class MaintenanceStatusResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    enabled: bool
    reason: str | None
    enabled_by: str | None
    enabled_at: float | None


class SetMaintenanceRequest(BaseModel):
    enabled: bool
    reason: str | None = None


def _store(request: Request) -> MaintenanceModeStore | None:
    return getattr(request.app.state, "maintenance_mode_store", None)


@router.get(
    "/maintenance",
    response_model=MaintenanceStatusResponse,
    summary="Get the broker's maintenance-mode status (no auth required)",
)
async def get_maintenance_status(request: Request) -> MaintenanceStatusResponse:
    store = _store(request)
    state = await store.get() if store is not None else MaintenanceState(
        enabled=False, reason=None, enabled_by=None, enabled_at=None
    )
    return MaintenanceStatusResponse(
        enabled=state.enabled,
        reason=state.reason,
        enabled_by=state.enabled_by,
        enabled_at=state.enabled_at,
    )


@router.post(
    "/maintenance",
    response_model=MaintenanceStatusResponse,
    summary="Toggle maintenance mode (admin only)",
)
async def set_maintenance_status(
    body: SetMaintenanceRequest,
    request: Request,
    principal: Annotated[Principal, Depends(require_admin)],
) -> MaintenanceStatusResponse:
    store = _store(request)
    state = MaintenanceState(
        enabled=body.enabled,
        reason=body.reason,
        enabled_by=principal.subject if body.enabled else None,
        enabled_at=time.time() if body.enabled else None,
    )
    if store is not None:
        await store.set(state)
    return MaintenanceStatusResponse(
        enabled=state.enabled,
        reason=state.reason,
        enabled_by=state.enabled_by,
        enabled_at=state.enabled_at,
    )
```

(`enabled_by`/`enabled_at` are cleared to `None` when disabling, so
"who/when it was last turned on" doesn't linger stale after it's off — worth
a second look/discussion if you'd rather preserve last-enabled history; the
design doc doesn't specify this, so this is a judgment call made here, not
implied.)

In `router.py`, add:

```python
from af_mcp_broker.api import admin, catalog_tools, ...

router.include_router(admin.router)  # no maintenance-mode dependency -- see Task C6's comment
```

**Step 4: Run test to verify it passes**

Run: `pixi run -e dev pytest broker/tests/test_admin_api.py -v`
Expected: PASS (4 tests)

**Step 5: Commit**

```bash
git add broker/src/af_mcp_broker/api/admin.py broker/src/af_mcp_broker/api/router.py broker/tests/test_admin_api.py
git commit -m "$(cat <<'EOF'
feat(broker): add admin maintenance-mode API

GET carries no auth so the portal can show a banner to everyone,
including whoever is currently blocked; POST requires admin-group
membership and stamps enabled_by/enabled_at server-side.

Assisted-by: Claude (Anthropic)
EOF
)"
```

---

### Task C10: Chart wiring for maintenance mode

**Files:**
- Modify: `charts/af-mcp-platform/values.yaml`
- Modify: `charts/af-mcp-platform/templates/_helpers.tpl`

**Step 1** — in `values.yaml`, add a block near `usage:` (after line 455's
`networkPolicy` block):

```yaml
  # Broker-wide maintenance mode (2026-08-28 admin capabilities design):
  # only admins get through /v1 and /mcp while enabled. Must be visible to
  # every replica consistently -- "in-memory" only ever affects the one
  # replica that handled the toggle request (the broker warns loudly at
  # startup if this is selected alongside replicaCount > 1); "vault" and
  # "postgres" propagate to every replica.
  maintenanceMode:
    backend: "in-memory"  # or "vault" or "postgres"
    # Path prefix under oauth21.tokenStore.vault.kvMount where the
    # maintenance-mode record is stored. Only meaningful when backend="vault".
    kvPathPrefix: "mcp/maintenance-mode"
    postgres:
      # Optional: reuse broker.usage.postgres's DSN when unset (both point at
      # the same database by default) -- set only if maintenance mode should
      # use a different database than the usage store.
      existingSecret:
        name: ""
        key: "uri"
```

**Step 2** — in `_helpers.tpl`, add after the `USAGE_POSTGRES_DSN` block
(after line 367's closing `{{- end }}{{- end }}`, before the tracing block):

```yaml
# Maintenance-mode backend (2026-08-28 admin capabilities design) -- always
# set, same visibility rationale as TOKEN_STORE_BACKEND above.
- name: MAINTENANCE_MODE_BACKEND
  value: {{ .Values.broker.maintenanceMode.backend | replace "-" "_" | quote }}
{{- if .Values.broker.maintenanceMode.kvPathPrefix }}
- name: MAINTENANCE_MODE_KV_PATH_PREFIX
  value: {{ .Values.broker.maintenanceMode.kvPathPrefix | quote }}
{{- end }}
{{- if and (eq .Values.broker.maintenanceMode.backend "postgres") .Values.broker.maintenanceMode.postgres.existingSecret.name }}
# asyncpg DSN for the postgres maintenance-mode store. Omit this secret
# entirely to reuse broker.usage.postgres's DSN instead (Settings.
# maintenance_mode_effective_postgres_dsn falls back to it).
- name: MAINTENANCE_MODE_POSTGRES_DSN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.broker.maintenanceMode.postgres.existingSecret.name | quote }}
      key: {{ .Values.broker.maintenanceMode.postgres.existingSecret.key | quote }}
{{- end }}
```

**Step 3: Verify the chart still lints**

Run: `helm lint charts/af-mcp-platform`
Expected: no new errors/warnings.

Also check `charts/af-mcp-platform/ci/postgres-usage-values.yaml` — if there's
a chart-testing CI values file exercising the postgres usage backend, decide
whether it's worth adding a sibling case for
`maintenanceMode.backend: postgres` (matching how thoroughly that file
already covers the usage postgres path) — read it first before deciding
whether this is in scope for this task or a follow-up.

**Step 4: Commit**

```bash
git add charts/af-mcp-platform/values.yaml charts/af-mcp-platform/templates/_helpers.tpl
git commit -m "$(cat <<'EOF'
feat(chart): wire maintenance-mode backend settings

Assisted-by: Claude (Anthropic)
EOF
)"
```

---

### Task C11: Portal — maintenance banner + admin toggle

**Files:**
- Modify: `portal/src/lib/api.ts`
- Modify: `portal/src/layouts/Base.astro`
- Modify: `portal/src/components/AdminPage.vue`
- Test: `portal/src/components/__tests__/AdminPage.test.ts`, and a new
  banner test if Base.astro's script logic is factored into a testable `.ts`
  module (check whether `navSummary.ts` is the precedent for "logic lives in
  a plain .ts file, Base.astro just calls it" — if so, follow that pattern
  here too, e.g. a new `maintenanceBanner.ts`).

**Step 1** — add to `api.ts`:

```typescript
export interface MaintenanceStatus {
  enabled: boolean;
  reason: string | null;
  enabled_by: string | null;
  enabled_at: number | null;
}

export async function fetchMaintenanceStatus(): Promise<MaintenanceStatus> {
  // No Authorization header required (GET /v1/admin/maintenance takes none) --
  // but check whether this file's fetch helper always attaches one and, if
  // so, whether that's harmless here (an extra/expired bearer on a route
  // that ignores auth entirely should still 200) before assuming a bespoke
  // unauthenticated fetch is needed.
}

export async function setMaintenanceStatus(
  enabled: boolean,
  reason?: string
): Promise<MaintenanceStatus> {
  // POST, same auth-attaching fetch helper every other mutating call in this
  // file uses.
}
```

**Step 2: Write the failing test** for the toggle UI in `AdminPage.vue`
(banner test is separate, in whatever module the banner logic lives):

```typescript
it('shows a maintenance toggle and reflects its status', async () => {
  // mock fetchMaintenanceStatus to return {enabled: false, ...}
  const wrapper = mount(AdminPage);
  await flushPromises();
  expect(wrapper.find('[data-testid="maintenance-toggle"]').exists()).toBe(true);
});
```

**Step 3: Run test to verify it fails**

Expected: FAIL.

**Step 4: Write minimal implementation** — add a maintenance section to
`AdminPage.vue`:

```vue
<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { fetchMaintenanceStatus, setMaintenanceStatus, type MaintenanceStatus } from '../lib/api';
// ...existing usage-dropdown script...

const maintenance = ref<MaintenanceStatus | null>(null);
const reasonInput = ref('');

onMounted(async () => {
  maintenance.value = await fetchMaintenanceStatus();
});

async function toggleMaintenance(): Promise<void> {
  if (!maintenance.value) return;
  maintenance.value = await setMaintenanceStatus(!maintenance.value.enabled, reasonInput.value || undefined);
}
</script>

<template>
  <!-- ...existing usage-dropdown section... -->
  <section class="af-panel" v-if="maintenance">
    <h2>Maintenance mode</h2>
    <p>Status: {{ maintenance.enabled ? 'ON' : 'off' }}</p>
    <input v-model="reasonInput" placeholder="Reason (optional)" />
    <button data-testid="maintenance-toggle" @click="toggleMaintenance">
      {{ maintenance.enabled ? 'Disable' : 'Enable' }} maintenance mode
    </button>
  </section>
</template>
```

For the banner (shown to *every* visitor, not just admins), add a
`maintenanceBanner.ts` following `navSummary.ts`'s "logic in a plain module,
Base.astro wires it up" shape — read `navSummary.ts` first to match its
export shape (likely a pure function taking a response and returning
DOM-ready data, called from Base.astro's mount script). Wire it into
`Base.astro`'s existing mount script alongside the identities/dashboard-summary
fetches:

```typescript
import { fetchMaintenanceStatus } from '../lib/api';

fetchMaintenanceStatus()
  .then((status) => {
    if (status.enabled) {
      // reveal a banner element, following the same querySelector/hidden
      // pattern used for the admin nav entry in Task A6.
    }
  })
  .catch(() => {
    // banner stays hidden on fetch failure -- same fail-safe posture as
    // navBadges(null) and the admin-nav reveal.
  });
```

Add the banner markup itself (a `<div data-af-maintenance-banner hidden>`
somewhere prominent in `Base.astro`'s template, near the top).

**Step 5: Run test to verify it passes**

Expected: PASS.

**Step 6: Manually verify in the browser** — toggle maintenance mode as an
admin dev-bypass principal, confirm the banner appears for a *different*,
non-admin dev-bypass principal (switch `BROKER_DEV_INSECURE_PRINCIPAL`
between two terminal sessions, or two browser profiles), and confirm that
non-admin's other portal pages actually start failing (503) once maintenance
is on, per Task C6/C7's enforcement.

**Step 7: Commit**

```bash
git add portal/src/lib/api.ts portal/src/layouts/Base.astro portal/src/components/AdminPage.vue portal/src/lib/maintenanceBanner.ts portal/src/components/__tests__/AdminPage.test.ts
git commit -m "$(cat <<'EOF'
feat(portal): add maintenance-mode banner and admin toggle

The banner fetches GET /v1/admin/maintenance (no auth) so it's visible
to every visitor, including whoever is currently blocked by it.

Assisted-by: Claude (Anthropic)
EOF
)"
```

---

## Part D — Docs

### Task D1: Operator-facing admin docs

**Files:**
- Create: `docs/admin.md`
- Modify: `docs/index.md` (add it to whatever nav/TOC list exists there —
  read the file first to match its exact list format)

**Step 1** — write `docs/admin.md` covering, for an operator standing up a
new facility (mirror `docs/auth.md`'s narrative-then-reference style, much
shorter since this is a much smaller surface):

- What `broker.adminGroup` does and how to set it (chart value + the
  Keycloak group it should point at).
- The admin-only surfaces it gates: the portal's Admin page, `GET
  /v1/usage/subjects` + the `subject=` override on `GET /v1/usage`, and
  `POST /v1/admin/maintenance`.
- Maintenance mode: what it blocks (everything but health probes and the
  admin routes), how to toggle it (`POST /v1/admin/maintenance` or the
  portal), and the three backend choices with the same
  in-memory-single-replica caveat `docs/auth.md`'s principal-cache section
  already models for a very similar tradeoff.

**Step 2: Commit**

```bash
git add docs/admin.md docs/index.md
git commit -m "$(cat <<'EOF'
docs: add operator-facing admin capabilities guide

Assisted-by: Claude (Anthropic)
EOF
)"
```

---

## Final verification (after every task above)

```bash
pixi run -e dev lint-all          # ruff + mypy + pre-commit, broker
pixi run -e dev pytest broker/ -v # full broker suite
pixi run -e portal build          # what CI checks for the portal
helm lint charts/af-mcp-platform
```

All four must pass clean before moving to
`superpowers:finishing-a-development-branch` for the merge/PR decision.
