from __future__ import annotations


class BrokerError(Exception):
    """Base of every exception the broker itself defines.

    Subclasses mark an *expected* operational failure the broker translates
    into a controlled response (an HTTP status, an MCP tool error, an audit
    ``error_class``). Each subsystem owns the subclasses for the failures it
    raises -- see that subsystem's ``errors`` module, or the module that
    raises them for the top-level ones. This module deliberately imports
    nothing from any subsystem so every one of them can import it.

    An unexpected programming error (``TypeError``, ``KeyError`` from a bug,
    ...) is never wrapped in a ``BrokerError``: it must keep surfacing as an
    internal error.
    """
