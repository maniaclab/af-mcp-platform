from __future__ import annotations

# Default name of the registry's self-registered entry for the broker's own
# af_* methods (see ServiceRegistry's builtin entry). Configurable per
# deployment via BUILTIN_SERVICE_NAME (config.py) so a facility can align it
# with its service-naming convention -- the `<backend>_service` form here.
# Only the *name* is configurable; the reserved `af` prefix stays fixed
# because the method wire-names (af_whoami, ...) are built from it.
BUILTIN_SERVICE_NAME = "gateway_service"
