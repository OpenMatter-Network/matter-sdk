"""The package ships type information, and the native stub matches the module."""

import ast
import pathlib

import matter_sdk
from matter_sdk import _native

PACKAGE = pathlib.Path(matter_sdk.__file__).parent


def test_the_package_is_marked_typed():
    assert (PACKAGE / "py.typed").exists()


def test_the_native_stub_names_exactly_what_the_module_exports():
    tree = ast.parse((PACKAGE / "_native.pyi").read_text())
    stubbed = {
        node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))
    } | {
        node.target.id
        for node in tree.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    }
    exported = {name for name in dir(_native) if not name.startswith("_")}
    assert stubbed == exported, (sorted(stubbed - exported), sorted(exported - stubbed))
