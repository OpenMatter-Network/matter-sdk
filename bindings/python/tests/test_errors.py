"""The exception hierarchy is importable and catchable with or without the
``[sdk]`` extra."""

import ast
import pathlib

import pytest

import matter_sdk
from matter_sdk import errors

EXCEPTIONS = [
    "ChainError",
    "ReadOnlyError",
    "ConfigError",
    "WrongNetworkError",
    "MainnetNotConfirmedError",
    "NotPermittedError",
    "NeverAdmittedError",
    "KeyRevokedError",
    "UnsponsoredError",
    "DispatchError",
    "PoolRejectedError",
    "OuterDispatchError",
]


@pytest.mark.parametrize("name", EXCEPTIONS)
def test_every_chain_exception_is_a_real_class_exported_from_the_package(name):
    cls = getattr(matter_sdk, name)
    assert cls is getattr(errors, name)
    assert issubclass(cls, matter_sdk.ChainError)
    try:
        raise cls("boom")
    except matter_sdk.ChainError as exc:
        assert str(exc) == "boom"


def test_config_errors_stay_catchable_as_value_errors():
    assert issubclass(matter_sdk.ConfigError, ValueError)


def test_the_errors_module_needs_no_optional_dependency():
    source = pathlib.Path(errors.__file__).read_text()
    imported = {
        (node.module or "").split(".")[0]
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom)
    } | {
        alias.name.split(".")[0]
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert not imported & {"substrateinterface", "scalecodec"}, imported
