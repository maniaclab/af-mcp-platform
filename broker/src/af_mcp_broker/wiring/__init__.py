"""Builders that assemble the broker's subsystems at startup.

``app.lifespan`` is a short sequence of calls into this package, in
dependency order. Each builder takes explicit, typed inputs and returns a typed
result; a builder that owns a resource with a close registers that close on the
caller's ``AsyncExitStack``, so shutdown (and a failed startup) tears resources
down in reverse build order.

Builders that need only one subsystem's layer live next to it (for example
``maintenance.build_maintenance_store``); this package holds the glue that
needs several.
"""
