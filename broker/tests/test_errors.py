"""Every exception class the broker defines derives from ``BrokerError``."""

from __future__ import annotations

import importlib
import inspect
import pkgutil

import af_mcp_broker
from af_mcp_broker.errors import BrokerError


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
    )
    assert offenders == [], f"exceptions not deriving from BrokerError: {offenders}"
