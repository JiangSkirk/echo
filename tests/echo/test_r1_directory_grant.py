"""R1-C: DirectoryGrant pure leaf contract tests."""
from __future__ import annotations

import ast
import dataclasses
import hashlib
import importlib
import inspect
import re
import shutil
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "js" / "echo" / "mode_contract.py"
PRODUCTION_ROOTS = (ROOT / "js", ROOT / "js_work")


def contract() -> Any:
    return importlib.import_module("js.echo.mode_contract")


def make_grant(mod: Any, *, mode: Any = None, root: str = "/home/user/docs",
               workspace: str | None = "ws-a") -> Any:
    c = contract()
    actual_mode = mode or c.AppMode.WORK
    if actual_mode is c.AppMode.PERSONAL:
        workspace = None
    return mod.DirectoryGrantV1(
        mode=actual_mode,
        workspace=workspace,
        root=root,
    )


def test_public_symbols_exist() -> None:
    mod = contract()
    assert mod.DIRECTORY_GRANT_SCHEMA_VERSION == 1
    assert mod.DIRECTORY_GRANT_HASH_DOMAIN == b"js-agent:directory-grant:v1\0"
    assert issubclass(mod.DirectoryGrantValidationError, mod.ModeContractError)
    assert mod.DirectoryGrantValidationError is not mod.TaskRefValidationError
    assert dataclasses.is_dataclass(mod.DirectoryGrantV1)
    assert mod.DirectoryGrantV1.__slots__ == ("mode", "workspace", "root")
    sig = inspect.signature(mod.DirectoryGrantV1)
    assert list(sig.parameters) == ["mode", "workspace", "root"]
    assert all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in sig.parameters.values())


def test_subclass_rejected() -> None:
    mod = contract()
    with pytest.raises(TypeError):
        class EvilGrant(mod.DirectoryGrantV1):
            pass


def test_personal_grant_has_null_workspace() -> None:
    mod = contract()
    grant = make_grant(mod, mode=mod.AppMode.PERSONAL)
    assert grant.workspace is None
    assert grant.mode is mod.AppMode.PERSONAL


def test_work_grant_requires_workspace() -> None:
    mod = contract()
    with pytest.raises(mod.DirectoryGrantValidationError):
        mod.DirectoryGrantV1(
            mode=mod.AppMode.WORK,
            workspace=None,
            root="/home/user/docs",
        )


def test_root_must_be_absolute_path_string() -> None:
    mod = contract()
    for bad in ["relative/path", "", "  /path", "/path  ", "../etc", 1, True, None]:
        with pytest.raises(mod.DirectoryGrantValidationError):
            mod.DirectoryGrantV1(
                mode=mod.AppMode.WORK,
                workspace="ws-a",
                root=bad,
            )


def test_schema_version_is_constant_property() -> None:
    mod = contract()
    grant = make_grant(mod)
    assert grant.schema_version == 1


def test_serialization_round_trip() -> None:
    mod = contract()
    grant = make_grant(mod)
    d = grant.to_dict()
    assert set(d.keys()) == {"schema_version", "mode", "workspace", "root"}
    assert d["schema_version"] == 1
    assert d["mode"] == "work"
    assert d["workspace"] == "ws-a"
    assert d["root"] == "/home/user/docs"
    restored = mod.DirectoryGrantV1.from_dict(d)
    assert restored == grant


def test_from_dict_rejects_unknown_fields() -> None:
    mod = contract()
    d = make_grant(mod).to_dict()
    d["evil"] = "data"
    with pytest.raises(mod.DirectoryGrantValidationError) as exc:
        mod.DirectoryGrantV1.from_dict(d)
    assert "unknown_field" in str(exc.value)


def test_from_dict_rejects_missing_fields() -> None:
    mod = contract()
    d = make_grant(mod).to_dict()
    del d["root"]
    with pytest.raises(mod.DirectoryGrantValidationError) as exc:
        mod.DirectoryGrantV1.from_dict(d)
    assert "missing_field" in str(exc.value)


def test_from_dict_rejects_non_dict_root() -> None:
    mod = contract()
    with pytest.raises(mod.DirectoryGrantValidationError):
        mod.DirectoryGrantV1.from_dict(None)
    with pytest.raises(mod.DirectoryGrantValidationError):
        mod.DirectoryGrantV1.from_dict([])


def test_canonical_hash_format() -> None:
    mod = contract()
    grant = make_grant(mod)
    h = grant.canonical_hash()
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", h)
    expected = "sha256:" + hashlib.sha256(
        mod.DIRECTORY_GRANT_HASH_DOMAIN + grant.canonical_bytes()
    ).hexdigest()
    assert h == expected


def test_grant_is_subset_of() -> None:
    mod = contract()
    broad = make_grant(mod, root="/home/user")
    narrow = make_grant(mod, root="/home/user/docs")
    assert narrow.is_subset_of(broad)
    assert not broad.is_subset_of(narrow)


def test_subset_rejects_different_mode() -> None:
    mod = contract()
    work_grant = make_grant(mod, mode=mod.AppMode.WORK)
    personal_grant = make_grant(mod, mode=mod.AppMode.PERSONAL)
    with pytest.raises(mod.DirectoryGrantValidationError):
        work_grant.is_subset_of(personal_grant)


def test_subset_rejects_wrong_type() -> None:
    mod = contract()
    grant = make_grant(mod)
    with pytest.raises(mod.DirectoryGrantValidationError):
        grant.is_subset_of(object())


def test_grant_contains_no_owner_session_run_or_credentials() -> None:
    mod = contract()
    grant = make_grant(mod)
    d = grant.to_dict()
    for forbidden in ("owner", "session", "run", "token", "key", "secret", "credential"):
        assert forbidden not in d
        assert forbidden not in str(d).lower()


_GRANT_DIRECT_CONSUMER = Path("js/connectors/contracts.py")
_GRANT_REEXPORT_CONSUMERS = frozenset(
    {
        Path("js/connectors/__init__.py"),
        Path("js/connectors/base.py"),
        Path("js/connectors/local.py"),
    }
)


def _assert_exact_directory_grant_consumers(root: Path) -> None:
    """Keep R1 pure while allowing only the approved R4 authority edge.

    ``mode_contract`` remains a runtime/I/O-free leaf.  R4 contracts import the
    exact frozen type once; connector shells may only reuse that same identity
    through ``js.connectors.contracts``.  No other production module may gain a
    grant import or define/alias a competing authority type.
    """

    module_path = root / "js" / "echo" / "mode_contract.py"
    production_roots = (root / "js", root / "js_work")
    for production_root in production_roots:
        for path in production_root.rglob("*.py"):
            if path == module_path:
                continue
            relative = path.relative_to(root)
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(relative))
            for node in ast.walk(tree):
                if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    assert node.name not in {"DirectoryGrant", "DirectoryGrantV1"}, (
                        f"competing directory grant definition found in {relative}"
                    )
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                    targets: list[ast.expr]
                    if isinstance(node, ast.Assign):
                        targets = node.targets
                    else:
                        targets = [node.target]
                    assert not any(
                        isinstance(target, ast.Name)
                        and target.id in {"DirectoryGrant", "DirectoryGrantV1"}
                        for target in targets
                    ), f"directory grant alias found in {relative}"
                if isinstance(node, ast.ImportFrom):
                    imported_names = {alias.name for alias in node.names}
                    if "DirectoryGrantValidationError" in imported_names:
                        raise AssertionError(
                            f"DirectoryGrantValidationError consumer found in {relative}"
                        )
                    if "DirectoryGrantV1" not in imported_names:
                        continue
                    aliases = [alias for alias in node.names if alias.name == "DirectoryGrantV1"]
                    assert all(alias.asname is None for alias in aliases), (
                        f"DirectoryGrantV1 alias import found in {relative}"
                    )
                    if relative == _GRANT_DIRECT_CONSUMER:
                        assert node.module == "js.echo.mode_contract", (
                            f"direct grant consumer must import R1 identity in {relative}"
                        )
                    else:
                        assert relative in _GRANT_REEXPORT_CONSUMERS, (
                            f"unapproved DirectoryGrantV1 import found in {relative}"
                        )
                        assert node.module == "js.connectors.contracts", (
                            f"connector grant reuse must come from contracts in {relative}"
                        )
                if isinstance(node, ast.Call):
                    call_name = (
                        node.func.id
                        if isinstance(node.func, ast.Name)
                        else node.func.attr
                        if isinstance(node.func, ast.Attribute)
                        else ""
                    )
                    if call_name not in {"getattr", "__import__", "import_module"}:
                        continue
                    string_args = [
                        argument.value
                        for argument in node.args
                        if isinstance(argument, ast.Constant)
                        and isinstance(argument.value, str)
                    ]
                    assert not any("DirectoryGrant" in value for value in string_args), (
                        f"dynamic directory grant lookup found in {relative}"
                    )


def test_no_unapproved_production_callsites() -> None:
    _assert_exact_directory_grant_consumers(ROOT)
    connector_contracts = importlib.import_module("js.connectors.contracts")
    assert connector_contracts.DirectoryGrantV1 is contract().DirectoryGrantV1
    field = next(
        item
        for item in dataclasses.fields(connector_contracts.ConnectorExecutionRequestV1)
        if item.name == "directory_grant"
    )
    assert "DirectoryGrantV1" in str(field.type)


def test_unapproved_production_consumer_mutation_is_rejected(tmp_path: Path) -> None:
    mutation_root = tmp_path / "source"
    shutil.copytree(ROOT / "js", mutation_root / "js")
    shutil.copytree(ROOT / "js_work", mutation_root / "js_work")
    injected = mutation_root / "js" / "unapproved_grant_consumer.py"
    injected.write_text(
        "from js.echo.mode_contract import DirectoryGrantV1\n"
        "def use(grant: DirectoryGrantV1) -> str:\n"
        "    return grant.root\n",
        encoding="utf-8",
    )

    with pytest.raises(AssertionError, match="unapproved DirectoryGrantV1 import"):
        _assert_exact_directory_grant_consumers(mutation_root)


def test_no_io_in_module() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported = ".".join(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported = node.module or ""
        else:
            continue
        if imported:
            assert not any(
                x in imported
                for x in ("os", "pathlib", "socket", "urllib", "requests", "subprocess", "time", "random")
            ), f"forbidden import: {imported}"


# ============================================================
# R1-F08: Path normalization
# ============================================================

def test_trailing_slash_rejected() -> None:
    """Non-root paths with trailing slash must be rejected."""
    mod = contract()
    with pytest.raises(mod.DirectoryGrantValidationError):
        mod.DirectoryGrantV1(mode=mod.AppMode.WORK, workspace="ws-a", root="/a/b/")


def test_root_path_allowed() -> None:
    """Root path '/' must be allowed."""
    mod = contract()
    grant = mod.DirectoryGrantV1(mode=mod.AppMode.WORK, workspace="ws-a", root="/")
    assert grant.root == "/"


def test_double_slash_rejected() -> None:
    """Double slashes must be rejected."""
    mod = contract()
    with pytest.raises(mod.DirectoryGrantValidationError):
        mod.DirectoryGrantV1(mode=mod.AppMode.WORK, workspace="ws-a", root="/a//b")


def test_dot_segment_rejected() -> None:
    """Dot segments must be rejected."""
    mod = contract()
    with pytest.raises(mod.DirectoryGrantValidationError):
        mod.DirectoryGrantV1(mode=mod.AppMode.WORK, workspace="ws-a", root="/a/./b")


def test_dotdot_segment_rejected() -> None:
    """Dotdot segments must be rejected."""
    mod = contract()
    with pytest.raises(mod.DirectoryGrantValidationError):
        mod.DirectoryGrantV1(mode=mod.AppMode.WORK, workspace="ws-a", root="/a/../b")


def test_non_nfc_rejected() -> None:
    """Non-NFC Unicode must be rejected."""
    mod = contract()
    # NFD form of é (e + combining accent)
    nfd_e = "e\u0301"
    with pytest.raises(mod.DirectoryGrantValidationError):
        mod.DirectoryGrantV1(mode=mod.AppMode.WORK, workspace="ws-a", root="/a/" + nfd_e)


def test_unicode_path_allowed() -> None:
    """NFC Unicode paths with internal spaces must be allowed."""
    mod = contract()
    grant = mod.DirectoryGrantV1(mode=mod.AppMode.WORK, workspace="ws-a", root="/home/user/文档")
    assert grant.root == "/home/user/文档"


def test_subset_path_parts_not_string_prefix() -> None:
    """/a/bad must not be subset of /a/b (string prefix would say yes)."""
    mod = contract()
    broad = mod.DirectoryGrantV1(mode=mod.AppMode.WORK, workspace="ws-a", root="/a/b")
    narrow = mod.DirectoryGrantV1(mode=mod.AppMode.WORK, workspace="ws-a", root="/a/bad")
    assert not narrow.is_subset_of(broad)


def test_subset_deeper_path() -> None:
    """/a/b/c must be subset of /a/b."""
    mod = contract()
    broad = mod.DirectoryGrantV1(mode=mod.AppMode.WORK, workspace="ws-a", root="/a/b")
    narrow = mod.DirectoryGrantV1(mode=mod.AppMode.WORK, workspace="ws-a", root="/a/b/c")
    assert narrow.is_subset_of(broad)


def test_subset_same_root() -> None:
    """Same root must be subset."""
    mod = contract()
    g1 = mod.DirectoryGrantV1(mode=mod.AppMode.WORK, workspace="ws-a", root="/a/b")
    g2 = mod.DirectoryGrantV1(mode=mod.AppMode.WORK, workspace="ws-a", root="/a/b")
    assert g1.is_subset_of(g2)


def test_subset_root_is_superset_of_all() -> None:
    """Root / must be superset of any path."""
    mod = contract()
    root = mod.DirectoryGrantV1(mode=mod.AppMode.WORK, workspace="ws-a", root="/")
    deep = mod.DirectoryGrantV1(mode=mod.AppMode.WORK, workspace="ws-a", root="/a/b/c")
    assert deep.is_subset_of(root)
