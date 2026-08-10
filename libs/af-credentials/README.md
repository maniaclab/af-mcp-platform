# af-credentials

Backend-side client for the AF MCP platform's broker-issued credentials
(issue #112). Import package: `af_credentials`. No dependency on
`af_mcp_broker`, FastAPI, or Kubernetes — this is meant to be embedded in
*other* MCP backends that need to trust the broker (ami-mcp's broker mode
today, later rucio-mcp), so it stays deliberately thin: `pyjwt[crypto]` and
`httpx2` at runtime, `mcp>=2.0.0,<3` opt-in via the `[mcp]` extra.

## `BrokerTokenVerifier` (`af_credentials.verifier`)

Verifies an **AF Broker Identity Token** — the RS256 identity assertion
`af_mcp_broker.credentials.broker_issued.BrokerTokenIssuer` mints for
AF-native backends (see the platform's `docs/auth.md`, "AF Broker Identity
Token"). The claim set is exactly `iss`/`sub`/`aud`/`exp`/`iat`/`jti`, plus
`uid`/`gid`/`unixname` only when the issuing broker's target config
requested POSIX identity — never a capability or group claim.

```python
from af_credentials.verifier import BrokerTokenVerifier

verifier = BrokerTokenVerifier(
    jwks_url="https://mcp.af.uchicago.edu/.well-known/jwks.json",
    issuer="https://mcp.af.uchicago.edu",
    audience="ami-mcp",
)

claims = await verifier.verify(token)
if claims is None:
    ...  # not authenticated: bad signature, wrong iss/aud, expired, ...
else:
    claims.sub, claims.jti, claims.exp  # always present
    claims.uid, claims.gid, claims.unixname  # None unless this token carries POSIX identity
```

JWKS keys are cached in-process for `cache_ttl` seconds (default 300),
keyed by `kid`. A token whose `kid` isn't in the current cache triggers
**exactly one** refetch, to pick up a key rotated in since the last fetch
(see the platform's key-rotation procedure) — if the refetched JWKS still
doesn't carry that `kid`, verification fails without fetching again.

`verify()` returns `None` for every way a token can be *invalid* (bad
signature, wrong issuer/audience, expired, malformed, unknown key), so
callers can treat "not authenticated" uniformly. It does **not** catch
transport failures — a JWKS fetch that can't connect, times out, or gets a
non-2xx response raises the underlying `httpx2` exception, so a caller can
tell "the broker is unreachable" apart from "this token is bad" and
respond accordingly (e.g. a 503 vs. a 401).

### `mcp_token_verifier()` (`af_credentials.mcp`, requires the `[mcp]` extra)

Adapts a `BrokerTokenVerifier` to the `mcp` SDK's `TokenVerifier` protocol,
for wiring an AF Broker Identity Token straight into a FastMCP/mcp server's
auth configuration:

```python
from af_credentials.mcp import mcp_token_verifier

token_verifier = mcp_token_verifier(verifier)  # implements mcp.server.auth.provider.TokenVerifier
```

`verify_token(token)` returns `AccessToken(token=token, client_id=claims.sub,
scopes=[], expires_at=claims.exp)` or `None`. `scopes` is always empty —
the token itself carries no authorization claims, so a server wanting
authorization must resolve it from `client_id` (the token's `sub`) itself,
not from this adapter's output.

**Known limitation:** this extra declares `mcp>=2.0.0,<3`, anticipating the
mcp SDK's next major version's finalized auth-provider shape. As of this
writing the af-mcp-platform monorepo's own pixi workspace still solves
`mcp==1.28.1` (transitively, via the broker feature's `fastmcp>=2.0`), so
the `credentials`/`dev` pixi environments install `af-credentials` *without*
this extra and its test suite exercises the adapter against that 1.x
install instead (`pytest.importorskip("mcp")` finds it present via the
`broker` feature) — the module code itself has no explicit version check,
so it works against 1.28.1 today. Revisit once an `mcp` 2.x release exists.

## `ProxyClient` (`af_credentials.proxy`)

Redeems a brokered x509/VOMS proxy. **Codes against a contract the broker
does not implement yet** (issue #112) — the redeem endpoint below is a
specification for the broker-side work to land against, not a live API.

```python
from af_credentials.proxy import ProxyClient, ProxyNotAvailableError, ProxyRedeemError

client = ProxyClient("https://mcp.af.uchicago.edu")

try:
    with await client.proxy_file(bearer_token) as handle:
        # handle.path   -> Path to a private 0600 PEM file (proxy cert + key)
        # handle.dn     -> VOMS proxy subject DN
        # handle.expires_at -> datetime
        run_subprocess(env={"X509_USER_PROXY": str(handle.path)})
    # file is deleted here, on __exit__
except ProxyNotAvailableError:
    ...  # no proxy available for this caller right now (no linked .globus,
         # or the broker's own cached proxy is too close to expiry)
except ProxyRedeemError as exc:
    ...  # the broker rejected/failed the call; exc.status_code, exc.detail
```

Use `pem_bytes(bearer_token)` instead of `proxy_file()` when the caller
wants the PEM material in-memory rather than as a file.

### The redeem contract

```
POST {broker_url}/v1/credentials/x509/redeem
Authorization: Bearer <token>
Content-Type: application/json

{}
```

A 200 response:

```json
{
  "pem": "<PEM-encoded proxy certificate + key>",
  "dn": "<VOMS proxy subject DN>",
  "voms_attributes": ["<VOMS FQAN>", "..."],
  "expires_at": "<ISO-8601 timestamp>",
  "remaining_seconds": 3600
}
```

- **404** → `ProxyNotAvailableError(detail)` — the response's `detail`
  field (or raw body if not JSON) is the exception's `.detail`.
- Any other non-200 → `ProxyRedeemError(status_code, detail)`.
- A 200 response whose `remaining_seconds` is below the client's
  `min_remaining` (default 60s) is *also* treated as
  `ProxyNotAvailableError` — the broker caches the proxy itself, so a
  caller who retried "the credential I just got" would just get the same
  near-expired proxy back.

`ProxyClient` never caches handles across calls — every `proxy_file()`/
`pem_bytes()` call redeems fresh (the broker is expected to be the one
doing the caching). Materialized files live under a private, 0700
directory created lazily on first use and reused for the lifetime of the
`ProxyClient` instance; each file inside it is written 0600.

## Development

```bash
pixi run -e dev test-credentials       # pytest libs/af-credentials/tests -v
pixi run -e dev lint-credentials       # ruff check + format --check
pixi run -e dev typecheck-credentials  # mypy --strict
```

`pixi run -e dev lint-all` / `test-all` (what CI runs) include all three.
