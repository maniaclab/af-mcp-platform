# Audience-mismatch error UI

## Problem

When a user's Keycloak token is missing the `mcp-gateway` audience — because
group membership never granted them the `read-token` role that gates the
scope's audience mapper (see `docs/auth.md`'s "Client scope Scope tab" and
"cascading failure" sections) — every `/v1` call 401s with the same generic
`{"detail": "Invalid or expired token"}` the broker returns for an actually
expired token.

The portal (`portal/src/lib/api.ts`) treats every unrenewable 401 as
`SessionExpiredError` and tells the user to reload. For an audience
mismatch, reloading (or the silent refresh-token renew `authFetch` already
attempts) can't fix anything — the user's account is permanently missing
the audience until an administrator changes their group membership. The
portal's "Session expired ... Reload" prompt is actively misleading for
this case, and repeated reloads just repeat the same 401 across every page
(the reported symptom: a wall of 401s on `/overview`, `/catalog`, etc.).

## Design

Distinguish the two cases end to end, and give the audience-mismatch case
the same treatment `backendStatus.ts` already gives `capability_required`/
`misconfigured`: an admin-actionable message plus a `correlation_id` to
quote, no hardcoded contact link, no reload button.

### Broker (`broker/src/af_mcp_broker/identity.py`)

- New `TokenAudienceError(HTTPException)`, sibling to the existing
  `TokenExpiredError`. Same rationale as that class's docstring: an
  audience mismatch reveals nothing about why any *other* token would be
  rejected, so it's safe to state explicitly rather than fold into the
  generic 401 detail.
- `get_principal` gains a `jwt.InvalidAudienceError` except-clause, placed
  before the existing broader `jwt.InvalidTokenError` clause (it's a
  subclass, so ordering matters). On catch: mint
  `correlation_id = uuid.uuid4().hex` (same pattern as
  `api/capabilities.py::_backend_status`), log it via structlog, and raise
  `TokenAudienceError` with a structured `detail`:

  ```python
  detail={
      "error": "insufficient_scope",
      "message": (
          "Your account is not authorized to use this platform yet. "
          "Contact your AF administrators and quote this ID: "
          f"{correlation_id}"
      ),
      "correlation_id": correlation_id,
  }
  ```

- `keycloak_dependency` (`/v1`) needs no change — it already lets
  `HTTPException` subclasses bubble to FastAPI's default handler unchanged,
  so this detail reaches the portal automatically.
- `/mcp`'s `AsgiAuthMiddleware` (`mcp/middleware/identity_mw.py`) needs no
  change either — `TokenAudienceError` falls into its existing generic
  `except HTTPException` branch, which deliberately stays vague on that
  surface (its docstring: "never repeat which claim, issuer/audience, or
  JWKS detail failed to a client"). Not extending the specific message to
  `/mcp` clients; this is scoped to the portal-facing surface only.

### Portal (`portal/src/lib/api.ts`)

New error class alongside `SessionExpiredError`:

```typescript
export class AccessDeniedError extends Error {
  constructor(
    message: string,
    public readonly correlationId: string | null,
  ) {
    super(message);
    this.name = 'AccessDeniedError';
  }
}
```

In `authFetch`, at the point that currently calls `throwSessionExpired()`
for a still-401-after-renew response: parse the body once and check for the
structured shape (`detail.error === "insufficient_scope"`). When it
matches, throw `AccessDeniedError` with the broker's own `message` and
`correlation_id` instead. Any other 401 shape (plain string detail, parse
failure, etc.) falls through to `throwSessionExpired()` exactly as today —
no behavior change for genuine session expiry.

### Portal UI (`CatalogPage.vue`, `IdentitiesPage.vue`, `TokensPage.vue`)

Each gets an `accessDenied` ref alongside its existing `sessionExpired`
ref, caught the same way in `onMounted`, and a new template block using the
component's existing `*__error` scoped class:

```html
<div v-else-if="accessDenied" class="cp__error" role="alert">
  <span class="cp__error-title">Access not yet granted</span>
  <span class="cp__error-body">{{ accessDenied.message }}</span>
</div>
```

No reload button, no contact link — the broker's own message (which
already ends with "contact your AF administrators, quote ID: …") is the
entire body. This matches `backendStatus.ts`'s existing convention for
`capability_required`: the detail sentence already says to contact admins,
and the correlation id is what gets quoted, with no per-facility contact
config needed.

## Testing

- Broker: `get_principal` raises `TokenAudienceError` with
  `detail["error"] == "insufficient_scope"` and a `correlation_id` for a
  token whose `aud` doesn't include `settings.oidc_audience`; a `/v1` route
  returns that shape verbatim.
- Portal: `authFetch`/`apiFetch` unit tests — a 401 with the structured
  detail throws `AccessDeniedError` with the right `correlationId`; a
  plain-string 401 still throws `SessionExpiredError` (no regression).
- No new Vue component-mount tests — this repo deliberately avoids those
  (see `backendStatus.ts`'s docstring); the three pages just wire the
  already-tested `authFetch` behavior through.
