from __future__ import annotations

# Default name of the registry's self-registered entry for the broker's own
# af_* methods (see ServiceRegistry's builtin entry). Configurable per
# deployment via BUILTIN_SERVICE_NAME (config.py) so a facility can align it
# with its service-naming convention -- the `<backend>_service` form here.
# Only the *name* is configurable; the reserved `af` prefix stays fixed
# because the method wire-names (af_whoami, ...) are built from it.
BUILTIN_SERVICE_NAME = "gateway_service"

# Bounded retry budget for the read-modify-write CAS loops over the token
# registry and the Vault principal cache -- a genuine conflict storm this deep
# would indicate something pathological (far beyond two replicas racing once),
# so failing loudly past this point is preferable to retrying forever.
MAX_CAS_RETRIES = 5

# asyncpg.create_pool()'s own defaults are min_size=10, max_size=10 --
# eagerly opening 10 connections per replica at start(), regardless of
# actual load. The usage store and the maintenance-mode store commonly share
# one small Postgres instance and, in production, with a second broker
# deployment pointed at a sibling database on the same server -- the
# unbounded defaults exhausted the instance max_connections during a
# routine rolling restart, once a second platform instance (sharing the same
# Postgres server) was stood up alongside this one (2026-09-19 production
# incident). Bounded down here rather than left at the driver default.
POOL_MIN_SIZE = 1
POOL_MAX_SIZE = 5
