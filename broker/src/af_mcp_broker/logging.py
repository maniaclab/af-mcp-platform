from __future__ import annotations

import logging
import sys
import time
import uuid
from typing import TYPE_CHECKING, Any, TextIO

import structlog

if TYPE_CHECKING:
    from structlog.stdlib import BoundLogger
    from structlog.types import EventDict, WrappedLogger

# Audit lines are emitted on this logger so they can be routed to their own
# destination (AUDIT_LOG_FILE) while sharing the processor chain, and hence
# the line shape, of every other log line. Not a parent of any other logger
# name (``af_mcp_broker.metering`` etc.), whose records would otherwise
# propagate into the audit destination.
AUDIT_LOGGER_NAME = "af_mcp_broker.audit.logger"

_MAX_CLIENT_REQUEST_ID_LENGTH = 128


class PassphraseRedactProcessor:
    """Replaces passphrase/password values before log records are emitted.

    Credentials must never appear in structured log output. This processor
    mutates the event dict in-place so that every layer of structlog's chain
    sees the redacted form.
    """

    _REDACTED_KEYS: frozenset[str] = frozenset({"passphrase", "password"})
    _REDACTED_VALUE: str = "[REDACTED]"

    def __call__(
        self,
        logger: WrappedLogger,  # noqa: ARG002 (structlog processor signature)
        method: str,  # noqa: ARG002 (structlog processor signature)
        event_dict: EventDict,
    ) -> EventDict:
        for key in self._REDACTED_KEYS:
            if key in event_dict:
                event_dict[key] = self._REDACTED_VALUE
        return event_dict


class _RaiseOnErrorMixin:
    """Makes a handler re-raise emit failures instead of printing them to stderr.

    ``logging.Handler.handleError`` swallows the exception by default; an
    audit line that could not be written must reach the caller.
    """

    def handleError(self, record: logging.LogRecord) -> None:  # noqa: ARG002 (stdlib hook signature)
        # Called from inside emit()'s ``except`` block, so this re-raises
        # the write failure.
        raise  # noqa: PLE0704


class AuditStdoutHandler(_RaiseOnErrorMixin, logging.StreamHandler):  # type: ignore[type-arg]
    """Audit handler writing to whatever ``sys.stdout`` is at emit time.

    Binding the stream at construction would pin a stdout that can later be
    closed (a captured stream under pytest, a replaced one in a embedding
    process); same technique as the stdlib's own stderr handler.
    """

    def __init__(self) -> None:
        logging.Handler.__init__(self)

    @property
    def stream(self) -> TextIO:  # type: ignore[override]
        return sys.stdout


class AuditFileHandler(_RaiseOnErrorMixin, logging.FileHandler):
    """Audit handler appending to a file."""


def configure_logging(log_level: str = "INFO", audit_log_file: str = "-") -> None:
    """Wire structlog to emit JSON lines to stdout.

    Audit lines (``AUDIT_LOGGER_NAME``) go to *audit_log_file* instead --
    ``"-"`` meaning stdout -- through the same formatter, and a failure to
    write one raises to the emitting call.

    Call once at application startup before any log statements.
    """
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        PassphraseRedactProcessor(),
    ]

    structlog.configure(
        processors=[
            *shared_processors,
            # stdlib compatibility: format_exc_info converts exc_info tuples
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.ExceptionRenderer(),
            structlog.processors.JSONRenderer(),
        ],
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(log_level.upper())

    audit_handler: logging.Handler = (
        AuditStdoutHandler()
        if audit_log_file == "-"
        else AuditFileHandler(audit_log_file)
    )
    audit_handler.setFormatter(formatter)
    audit_logger = logging.getLogger(AUDIT_LOGGER_NAME)
    audit_logger.handlers = [audit_handler]
    audit_logger.propagate = False

    # fastmcp gives its own logger a rich handler and stops propagation at
    # import; hand its records to the root handler so they are JSON lines too.
    fastmcp_logger = logging.getLogger("fastmcp")
    fastmcp_logger.handlers = []
    fastmcp_logger.propagate = True

    # Quieten noisy third-party loggers that we don't need at DEBUG
    for noisy in ("uvicorn.access", "httpx2", "httpcore2"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def close_audit_logging() -> None:
    """Close the audit destination opened by ``configure_logging``."""
    for handler in logging.getLogger(AUDIT_LOGGER_NAME).handlers:
        handler.close()


def bind_new_correlation_id() -> None:
    """Bind a fresh ``correlation_id`` to structlog's contextvars for the current request (issue #281).

    Call once at the very start of every request, before identity is
    resolved -- ``bind_subject`` below binds the caller's subject alongside
    it once a Principal exists, but a caller whose identity never resolves
    (an invalid token, say) still gets logged with a correlation_id, so
    even that failure can be traced back to one client call. Clears any
    contextvars first: without this, values bound by a previous request
    that happened to reuse the same task (e.g. ``subject`` from a prior
    call) would otherwise leak into this one's log lines.
    """
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(correlation_id=uuid.uuid4().hex)


def current_correlation_id() -> str:
    """Return the current request's ``correlation_id``, binding a fresh one if none is bound.

    Audit records, request lines and usage rows of one request share this id.
    A call made outside a request (no ASGI entry point bound one) gets a new
    id bound for the rest of the current context, so every line it emits
    still agrees.
    """
    correlation_id = structlog.contextvars.get_contextvars().get("correlation_id")
    if correlation_id is None:
        correlation_id = uuid.uuid4().hex
        structlog.contextvars.bind_contextvars(correlation_id=correlation_id)
    return correlation_id


def request_id_headers() -> dict[str, str]:
    """``X-Request-ID`` header carrying the current request's ``correlation_id`` (issue #342).

    Spread into the headers of every call to an AF-internal token service
    (servicex/voms/krb5/condor-token-service) so that service's audit line
    shares the id the broker logged, instead of minting an unrelated one.
    Empty when no correlation_id is bound (a call made outside a request).
    """
    correlation_id = structlog.contextvars.get_contextvars().get("correlation_id")
    return {"X-Request-ID": correlation_id} if correlation_id else {}


def bind_subject(subject: str) -> None:
    """Bind *subject* to structlog's contextvars for the rest of the current request (issue #281).

    Called from every Principal-resolution path -- ``identity.get_principal``
    (JWT), ``pat_auth.resolve_pat_principal`` (PAT), and the local-dev bypass
    on both /v1 and /mcp -- so every log line downstream of identity
    resolution, on either surface, carries who made the call.
    """
    structlog.contextvars.bind_contextvars(subject=subject)


def bind_client_request_id(client_request_id: str) -> None:
    """Bind the caller-supplied ``X-Request-ID`` as ``client_request_id`` for the rest of the current request.

    Recorded beside the broker's own ``correlation_id`` so a client can find
    its call by the id it chose; it is never forwarded or used as the
    ``correlation_id``, because an unauthenticated caller must not choose the
    id that joins the broker's, the audit log's and the backends' lines.
    Truncated, since the header is attacker-controlled.
    """
    structlog.contextvars.bind_contextvars(
        client_request_id=client_request_id[:_MAX_CLIENT_REQUEST_ID_LENGTH]
    )


def log_request_received(bound_logger: BoundLogger, *, method: str, path: str) -> float:
    """Log ``http.request.received`` and return a ``time.monotonic()`` start mark for ``log_request_finished`` (issue #322).

    Call once at each ASGI entry point (/v1's ``_bind_request_logging_context``
    middleware, /mcp's ``AsgiAuthMiddleware.__call__``), immediately after
    ``bind_new_correlation_id()`` and before any auth/credential/routing
    work -- so a request that stalls or dies downstream (queued behind other
    work, stuck in auth/principal resolution, or a connection that never
    completes) still leaves this line. Only ``method`` and ``path`` are
    logged -- no query string, headers, or body, matching the audit log's
    handling of sensitive data.
    """
    bound_logger.info("http.request.received", method=method, path=path)
    return time.monotonic()


def log_request_finished(
    bound_logger: BoundLogger,
    *,
    start_time: float,
    status_code: int | None,
    exc_type: str | None = None,
) -> None:
    """Log ``http.request.finished`` -- success, exception, or client disconnect (issue #322).

    Call once, in a ``finally`` block, paired with the ``log_request_received``
    call that returned *start_time*. ``duration_ms`` is wall time since that
    call, measured with the monotonic clock (not wall-clock time, which can
    jump). ``subject`` is deliberately not a parameter here: it's bound into
    structlog's contextvars by ``bind_subject`` once identity resolves, and
    ``configure_logging``'s ``merge_contextvars`` processor merges it into
    this line automatically whenever it's present by the time this is
    called -- threading it through by hand would just duplicate that.
    """
    duration_ms = (time.monotonic() - start_time) * 1000
    bound_logger.info(
        "http.request.finished",
        status_code=status_code,
        duration_ms=round(duration_ms, 2),
        exc_type=exc_type,
    )
