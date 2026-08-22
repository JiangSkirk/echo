from __future__ import annotations

import ast
import dataclasses
import hashlib
import importlib
import inspect
import re
from pathlib import Path
from typing import Any, cast

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "js" / "echo" / "mode_contract.py"
PRODUCTION_ROOTS = (ROOT / "js", ROOT / "js_work")


def contract() -> Any:
    return importlib.import_module("js.echo.mode_contract")


def manifest(mod: Any, *, mode: Any = None, features: tuple[str, ...] = ("chat", "files"),
             tools: tuple[str, ...] = ("browser", "shell"),
             connectors: tuple[str, ...] = ("calendar", "drive")) -> Any:
    return mod.ModeManifestV1(
        mode=mod.AppMode.WORK if mode is None else mode,
        feature_ids=features,
        tool_ids=tools,
        connector_ids=connectors,
    )


def payload(mod: Any, **overrides: object) -> dict[str, object]:
    value = manifest(mod).to_dict()
    value.update(overrides)
    return value


def assert_error(exc: BaseException, *, code: str, field: str | None = None) -> None:
    error = cast("Any", exc)
    assert error.code == code
    assert error.field == field
    assert "sentinel-secret" not in str(error)


def test_public_frozen_leaf_contract() -> None:
    mod = contract()
    assert mod.MODE_MANIFEST_SCHEMA_VERSION == 1
    assert mod.MODE_MANIFEST_HASH_DOMAIN == b"js-agent:mode-manifest:v1\0"
    assert issubclass(mod.ModeManifestValidationError, mod.ModeContractError)
    assert mod.ModeManifestValidationError is not mod.TaskRefValidationError
    assert dataclasses.is_dataclass(mod.ModeManifestV1)
    assert mod.ModeManifestV1.__slots__ == ("mode", "feature_ids", "tool_ids", "connector_ids")
    sig = inspect.signature(mod.ModeManifestV1)
    assert list(sig.parameters) == ["mode", "feature_ids", "tool_ids", "connector_ids"]
    assert all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in sig.parameters.values())
    with pytest.raises(TypeError):
        class EvilManifest(mod.ModeManifestV1):
            pass
    with pytest.raises(TypeError):
        manifest(mod, workspace_required=True)


def test_mode_and_workspace_requirement_are_derived() -> None:
    mod = contract()
    personal = manifest(mod, mode=mod.AppMode.PERSONAL, features=(), tools=(), connectors=())
    work = manifest(mod)
    assert personal.mode is mod.AppMode.PERSONAL
    assert personal.schema_version == 1
    assert personal.workspace_required is False
    assert work.workspace_required is True
    assert personal.to_dict()["workspace_required"] is False
    assert work.to_dict()["workspace_required"] is True


@pytest.mark.parametrize("root", [None, [], (), "work", object()])
def test_from_dict_requires_exact_builtin_dict(root: object) -> None:
    mod = contract()
    with pytest.raises(mod.ModeManifestValidationError) as caught:
        mod.ModeManifestV1.from_dict(root)
    assert_error(caught.value, code="invalid_root")


@pytest.mark.parametrize("key", [1, True, type("S", (str,), {})("mode")])
def test_from_dict_rejects_non_builtin_keys(key: object) -> None:
    mod = contract()
    value = payload(mod)
    value.pop("mode")
    value[key] = "work"
    with pytest.raises(mod.ModeManifestValidationError) as caught:
        mod.ModeManifestV1.from_dict(value)
    assert_error(caught.value, code="invalid_key")


def test_from_dict_rejects_unknown_and_missing_fields_without_echo() -> None:
    mod = contract()
    value = payload(mod)
    value["sentinel-secret-key"] = "sentinel-secret"
    with pytest.raises(mod.ModeManifestValidationError) as unknown:
        mod.ModeManifestV1.from_dict(value)
    assert_error(unknown.value, code="unknown_field")
    missing = payload(mod)
    del missing["tool_ids"]
    with pytest.raises(mod.ModeManifestValidationError) as absent:
        mod.ModeManifestV1.from_dict(missing)
    assert_error(absent.value, code="missing_field", field="tool_ids")


@pytest.mark.parametrize("value", [True, 1.0, "1", None, 2])
def test_schema_version_is_exact_int_one(value: object) -> None:
    mod = contract()
    with pytest.raises(mod.ModeManifestValidationError) as caught:
        mod.ModeManifestV1.from_dict(payload(mod, schema_version=value))
    assert_error(caught.value, code="invalid_type" if type(value) is not int else "invalid_value", field="schema_version")


@pytest.mark.parametrize("value", ["WORK", "personal ", True, None, object()])
def test_mode_uses_strict_json_parser(value: object) -> None:
    mod = contract()
    with pytest.raises(mod.ModeManifestValidationError) as caught:
        mod.ModeManifestV1.from_dict(payload(mod, mode=value))
    assert_error(caught.value, code="invalid_value", field="mode")


@pytest.mark.parametrize("field", ["feature_ids", "tool_ids", "connector_ids"])
@pytest.mark.parametrize("value", [(), ("chat",), "chat", {"chat"}, type("L", (list,), {})(["chat"]), None])
def test_decoded_id_collections_require_exact_lists(value: object, field: str) -> None:
    mod = contract()
    with pytest.raises(mod.ModeManifestValidationError) as caught:
        mod.ModeManifestV1.from_dict(payload(mod, **{field: value}))
    assert_error(caught.value, code="invalid_type", field=field)


def test_decoded_exact_lists_are_accepted() -> None:
    mod = contract()
    value = mod.ModeManifestV1.from_dict(payload(mod, feature_ids=["chat"]))
    assert value.feature_ids == ("chat",)


@pytest.mark.parametrize(
    "bad",
    ["", " Chat", "chat ", "Chat", "chat/name", "chat\\name", "https://x", "a:b", "a..b",
     "a__b", "a--b", "a/../b", "a\u0000b", "e\u0301", "a" * 129, type("S", (str,), {})("chat"), 1, True],
)
def test_ids_are_strict_nfc_ascii_opaque_identifiers(bad: object) -> None:
    mod = contract()
    with pytest.raises(mod.ModeManifestValidationError) as caught:
        mod.ModeManifestV1.from_dict(payload(mod, feature_ids=[bad]))
    assert_error(caught.value, code="invalid_type" if type(bad) is not str else ("noncanonical_unicode" if bad == "e\u0301" else "invalid_value"), field="feature_ids")


@pytest.mark.parametrize("ids", [["files", "chat"], ["chat", "chat"], ["chat", "files", "files"]])
def test_decoded_ids_must_be_sorted_and_unique(ids: list[str]) -> None:
    mod = contract()
    with pytest.raises(mod.ModeManifestValidationError) as caught:
        mod.ModeManifestV1.from_dict(payload(mod, feature_ids=ids))
    assert cast("Any", caught.value).code in {"noncanonical_order", "duplicate_id"}


def test_direct_constructor_requires_exact_sorted_tuples() -> None:
    mod = contract()
    for value in (["chat"], ("files", "chat"), ("chat", "chat"), type("T", (tuple,), {})(["chat"])):
        with pytest.raises(mod.ModeManifestValidationError) as caught:
            manifest(mod, features=value)
        assert cast("Any", caught.value).code in {"invalid_type", "noncanonical_order", "duplicate_id"}


def test_direct_constructor_requires_exact_app_mode() -> None:
    mod = contract()

    class OtherMode(mod.StrEnum):
        WORK = "work"

    for value in ("work", type("S", (str,), {})("work"), OtherMode.WORK, True):
        with pytest.raises(mod.ModeManifestValidationError) as caught:
            manifest(mod, mode=value)
        assert_error(caught.value, code="invalid_type", field="mode")


def test_canonical_bytes_hash_and_round_trip() -> None:
    mod = contract()
    value = manifest(mod)
    assert value.canonical_bytes() == mod.canonical_json_bytes(value.to_dict())
    expected = "sha256:" + hashlib.sha256(mod.MODE_MANIFEST_HASH_DOMAIN + value.canonical_bytes()).hexdigest()
    assert value.canonical_hash() == expected
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", value.canonical_hash())
    assert mod.ModeManifestV1.from_dict(value.to_dict()) == value


def test_subset_intersection_and_narrow_cover_all_dimensions() -> None:
    mod = contract()
    broad = manifest(mod)
    narrow = manifest(mod, features=("chat",), tools=("browser",), connectors=("calendar",))
    assert narrow.is_subset_of(broad)
    assert not broad.is_subset_of(narrow)
    assert broad.intersect(narrow) == narrow
    reduced = broad.narrow(feature_ids=("chat",), tool_ids=("browser",), connector_ids=("calendar",))
    assert reduced == narrow
    assert reduced is not broad


def test_operations_reject_wrong_type_cross_mode_and_widening() -> None:
    mod = contract()
    value = manifest(mod)
    with pytest.raises(mod.ModeManifestValidationError) as wrong:
        value.is_subset_of(object())
    assert_error(wrong.value, code="invalid_operand")
    with pytest.raises(mod.ModeManifestValidationError) as mismatch:
        value.intersect(manifest(mod, mode=mod.AppMode.PERSONAL))
    assert_error(mismatch.value, code="mode_mismatch", field="mode")
    with pytest.raises(mod.ModeManifestValidationError) as subset_mismatch:
        value.is_subset_of(manifest(mod, mode=mod.AppMode.PERSONAL))
    assert_error(subset_mismatch.value, code="mode_mismatch", field="mode")
    with pytest.raises(mod.ModeManifestValidationError) as widen:
        value.narrow(tool_ids=("browser", "shell", "terminal"))
    assert_error(widen.value, code="capability_widening", field="tool_ids")


def test_operations_do_not_alias_or_mutate() -> None:
    mod = contract()
    value = manifest(mod)
    before = value.to_dict()
    out = value.narrow()
    out_dict = out.to_dict()
    out_dict["feature_ids"].append("later")  # type: ignore[union-attr]
    assert value.to_dict() == before
    assert out.to_dict() == before
    assert out is not value


def test_serialized_workspace_requirement_must_match_mode() -> None:
    mod = contract()
    with pytest.raises(mod.ModeManifestValidationError) as wrong:
        mod.ModeManifestV1.from_dict(payload(mod, workspace_required=False))
    assert_error(wrong.value, code="workspace_requirement_mismatch", field="workspace_required")
    with pytest.raises(mod.ModeManifestValidationError) as typed:
        mod.ModeManifestV1.from_dict(payload(mod, workspace_required=1))
    assert_error(typed.value, code="invalid_type", field="workspace_required")


def test_manifest_has_no_production_references_or_side_effects() -> None:
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
            assert not re.search(r"(?:os|pathlib|socket|urllib|requests|subprocess|secrets|time|random)", imported)
    for production_root in PRODUCTION_ROOTS:
        for path in production_root.rglob("*.py"):
            if path == MODULE_PATH:
                continue
            assert "ModeManifestV1" not in path.read_text(encoding="utf-8")
    assert "ModeManifestV1" in source
    assert not any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in {"open", "eval", "exec"} for n in ast.walk(tree))
