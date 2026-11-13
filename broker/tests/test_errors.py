"""Every exception class the broker defines derives from ``BrokerError``."""

from __future__ import annotations

import importlib
import inspect
import pkgutil

import af_mcp_broker
from af_mcp_broker.app import _IDENTITY_ERROR_RESPONSES
from af_mcp_broker.errors import BrokerError
from af_mcp_broker.identity import IdentityError
from af_mcp_broker.logging import CorrelatedHTTPException

# A transport type, not a domain error: it only carries an HTTP response.
_EXEMPT = (CorrelatedHTTPException,)


def _broker_modules():
    for info in pkgutil.walk_packages(
        af_mcp_broker.__path__, prefix=f"{af_mcp_broker.__name__}."
    ):
        yield importlib.import_module(info.name)


def test_every_exception_defined_in_the_package_is_a_broker_error() -> None:
    offenders = sorted(
        f"{module.__name__}.{name}"
        for module in _broker_modules()
        for name, obj in inspect.getmembers(module, inspect.isclass)
        if obj.__module__ == module.__name__
        and issubclass(obj, BaseException)
        and not issubclass(obj, BrokerError)
        and obj not in _EXEMPT
    )
    assert offenders == [], f"exceptions not deriving from BrokerError: {offenders}"


def test_every_identity_error_has_an_http_response() -> None:
    # app._identity_error_handler looks the exception's exact type up in this
    # table; a missing entry would turn into an unhandled 500.
    subclasses = {
        obj
        for module in _broker_modules()
        for _name, obj in inspect.getmembers(module, inspect.isclass)
        if obj.__module__ == module.__name__
        and issubclass(obj, IdentityError)
        and obj is not IdentityError
    }
    assert subclasses - set(_IDENTITY_ERROR_RESPONSES) == set()
