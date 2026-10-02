# HTCondor credmon integration

How a job submitted through condor-mcp gets the user's grid credentials on
the worker node -- an x509/VOMS proxy, a CERN Kerberos ticket, a ServiceX
token -- without the LLM agent ever seeing one. The broker stays the only
place credentials are minted; HTCondor's own credential pipeline (credd →
credmon → shadow → starter) carries them to the job.

Code references: `credmon/` (storer, sync loop, htcondor-api client, Vault
lease), `app.py` (the `af-credmon/<kind>` redeem audiences), `api/admin.py`
(`/v1/admin/credmon`), and the chart's `broker.credmon` values.

## The chain

```
broker (every replica polls; the lease holder runs a cycle every interval)
  for each user with a linked identity of kind K and a POSIX unixname:
    mint top token  = AF Broker Identity Token, aud=af-credmon/K, TTL 24h
    POST htcondor-api /api/v1/creds/service/af_K  {user, refresh: true}
      → credd writes  <creddir>/<user>/af_K.top

AP credmon (one daemon, scans <creddir>/*/af_*.top)
    POST broker /v1/credentials/K/redeem   (Bearer: the top token)
      → writes <creddir>/<user>/af_K.use   (ccache bytes / proxy PEM / token)

job:  use_oauth_services = af_krb5, af_x509
    shadow ships af_K.use → starter writes $_CONDOR_CREDS/af_K.use (0600,
    the job's user), re-sent every SEC_CREDENTIAL_REFRESH (default 300s)
```

The broker keeps **no copy** of the top token: it is a signed, self-verifying
JWT, and credd holds the only copy. The kind is in the `aud`, so an
`af-credmon/krb5` token is rejected by every other kind's redeem endpoint.
No condor service entry is involved -- each identity simply gains one more
consumer, resolved to that kind's first configured identity target (the same
default the user-facing `/v1` surfaces use).

Revocation is by expiry plus the redeem endpoint's own live checks: a user
who unlinks stops getting new top tokens, and their existing one stops
redeeming as soon as the identity is gone. There is no per-token early
revocation.

## Broker configuration

Off by default. In the chart:

```yaml
broker:
  identityToken:
    existingSigningKeySecret: broker-signing-key    # top tokens are broker JWTs
  credmon:
    enabled: true
    htcondorApiUrl: http://condor-mcp.mcp.svc.cluster.local:8080
    existingHtcondorApiTokenSecret: credmon-htcondor-api-token   # key: token
    kinds: [krb5, x509]          # empty = all three; unconfigured kinds skipped
    # topTokenTtlSeconds: 86400  # must exceed syncIntervalSeconds
    # syncIntervalSeconds: 14400
    prometheusRule:
      enabled: true
```

The equivalent env vars are `CREDMON_ENABLED`, `CREDMON_HTCONDOR_API_URL`,
`CREDMON_HTCONDOR_API_TOKEN_FILE`, `CREDMON_SERVICE_PREFIX` (default `af_`),
`CREDMON_KINDS`, `CREDMON_TOP_TOKEN_TTL_SECONDS`,
`CREDMON_SYNC_INTERVAL_SECONDS`, `CREDMON_SYNC_INTERNAL_TIMER` and
`CREDMON_STATE_KV_PATH_PREFIX`.

The broker refuses to boot when credmon is enabled without a signing key,
without Vault (users are enumerated from the Vault-backed identity stores,
and replicas coordinate through a Vault lease), without the Keycloak
principal directory (credd keys credentials by POSIX unixname), or with an
unreadable htcondor-api token file. A legacy-mode x509 entry (no
`serviceUrl`) has no Vault store, so x509 users are never enumerated there.

The htcondor-api bearer token must map to an identity in credd's
`CRED_SUPER_USERS`: the broker stores credentials on behalf of other users.

## Access point prerequisites

On the AP (the schedd host), the site needs:

```
DAEMON_LIST = $(DAEMON_LIST) CREDD
SEC_CREDENTIAL_DIRECTORY_OAUTH = /var/lib/condor/oauth_credentials
CRED_SUPER_USERS = <identity of the htcondor-api bearer token>
```

plus the AP credmon daemon (see below). UChicago's head01 currently runs
`DAEMON_LIST = MASTER SCHEDD` -- no credd and no OAuth credential directory.

**Coexisting with an existing `condor_credmon_oauth`.** Which credmon writes a
`.use` file is decided by configuration, not timing. The Local, Client and
Pelican credmons only claim names listed in their `*_PROVIDER_NAMES`, and
the OAuth2 credmon only refreshes `.use` files that have a `.meta` file, so
none of them touch `af_*`. The Vault credmon's default `*` wildcard does
claim unclaimed `.top` files: a site running it must set an explicit
`VAULT_CREDMON_PROVIDER_NAMES`. credd keeps a single `pid` file and
`CREDMON_COMPLETE` per credential directory, so when another credmon
already owns them the AP credmon must run in its poll-only mode.

`condor_submit` checks credentials at submit time (`CREDD_CHECK_CREDS`): an
`af_*` service passes only if its `.use` file already exists. The storer
runs ahead of submission, so a linked user's files are normally in place; a
user who links an identity just before submitting may need to wait for the
next cycle, or an admin can run one now (below).

## The AP credmon

The credmon is a long-running daemon on the AP (not part of this
repository). Its contract:

- scan `<creddir>/*/<prefix>*.top`; the kind is the filename minus the
  prefix and `.top`;
- read `access_token` from the `.top` JSON and call
  `POST <broker>/v1/credentials/<kind>/redeem` with it as the Bearer token --
  the same contract `af_credentials.ProxyClient` already implements;
- write `<creddir>/<user>/<prefix><kind>.use` atomically (temp file in the
  same directory, mode 0400, root-owned, rename) before it expires;
- on a 404 (identity no longer linked), remove the stale `.use`;
- primary mode: write `<creddir>/pid`, rescan on SIGHUP, touch
  `CREDMON_COMPLETE` after each scan. Poll-only mode: touch neither.

## Jobs

```
universe           = vanilla
executable         = run.sh
use_oauth_services = af_krb5, af_x509
queue
```

```bash
#!/bin/bash
# Reference credentials by path only -- never print them.
export KRB5CCNAME="FILE:${_CONDOR_CREDS}/af_krb5.use"
export X509_USER_PROXY="${_CONDOR_CREDS}/af_x509.use"
klist -s && voms-proxy-info -exists
exec python analysis.py
```

**Keep credentials out of job output.** HTCondor does not redact job stdout
or stderr, and condor-mcp's output and exec tools return them to the agent
verbatim. Scripts must reference `$_CONDOR_CREDS` files only through
environment variables like the above -- never `cat`, `base64` or `echo`
them. Only the short-lived `.use` credentials reach worker nodes; the top
token never leaves the AP credential directory. Keep
`SEC_DEBUG_PRINT_KEYS` off on the AP: it writes credentials into the
ShadowLog.

## Operating it

Only the replica holding the per-cycle lease runs a sync; every replica
answers status queries identically from the shared Vault record.

- **Portal → Admin**: the HTCondor credmon panel shows the last cycle, its
  per-kind counts and errors, and a "Run sync now" button.
- **`GET /v1/admin/credmon`** (admin only): the same record as JSON.
- **`POST /v1/admin/credmon/sync`** (admin only): run a cycle now from any
  replica; 409 while another replica is mid-cycle.
- **Metrics** (metrics port): `af_mcp_credmon_sync_runs_total{outcome,trigger}`
  (`success`, `partial`, `failed`, `skipped_lease`),
  `af_mcp_credmon_sync_last_success_timestamp_seconds`,
  `af_mcp_credmon_sync_credentials_total{kind,outcome}`,
  `af_mcp_credmon_sync_duration_seconds`. Every replica publishes the shared
  last success, so alert on `time() - max(...) > 2 × interval` -- the
  chart's optional PrometheusRule does exactly that.
- **Audit**: one `credmon_top_token_store` line per user and kind, never the
  token itself.

A failing sync never fails `/v1/readyz`: an htcondor-api outage should not
take the gateway down. A `partial` cycle (some users failed) still counts as
a success for alerting; its errors are in the status record.

## Known limitations

- Unlinking does not delete the user's `af_*` entry from credd; the top
  token expires within its TTL and stops redeeming immediately.
- A failed cycle is retried at the next interval, not sooner; the top-token
  TTL (default 6× the interval) covers missed cycles.
- There is no shipped CronJob alternative to the internal timer yet:
  `POST /v1/admin/credmon/sync` needs an admin Keycloak JWT.
