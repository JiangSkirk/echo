from __future__ import annotations

import ast
import hashlib
import importlib
import inspect
from collections.abc import Mapping
from dataclasses import FrozenInstanceError
from decimal import Decimal
from fractions import Fraction
from pathlib import Path
from typing import Any, cast

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "js" / "echo" / "mode_contract.py"
CHANGE_INVENTORY_ALLOWED_FILES = {
    "js/echo/mode_contract.py",
    "tests/echo/test_r1_client_task_adapter.py",
    "tests/echo/test_r1_mode_contract.py",
    "tests/echo/test_r1_mode_manifest.py",
}


def contract() -> Any:
    return importlib.import_module("js.echo.mode_contract")


def module_source() -> str:
    assert MODULE_PATH.exists(), "js.echo.mode_contract must exist"
    return MODULE_PATH.read_text(encoding="utf-8")


def module_tree() -> ast.Module:
    return ast.parse(module_source())


def base_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": 1,
        "mode": "work",
        "owner": "owner-a",
        "session": "session-a",
        "run": "run-a",
        "workspace": "work-a",
    }
    payload.update(overrides)
    return payload


def make_direct(mod: Any, **overrides: object) -> Any:
    payload = base_payload(**overrides)
    payload.pop("schema_version")
    return mod.TaskRef(**payload)


def assert_error(
    exc: BaseException,
    *,
    code: str,
    field: str | None,
    detail: str | None = None,
) -> None:
    error = cast("Any", exc)
    assert error.code == code
    assert error.field == field
    if detail is not None:
        assert error.detail == detail


class MyStr(str):
    pass


class AlwaysEqual:
    def __eq__(self, other: object) -> bool:
        return True


def test_task_ref_constructor_and_mode_field_are_strict_mypy_friendly() -> None:
    source = module_source()
    tree = ast.parse(source)
    task_ref = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "TaskRef")

    dataclass_decorator = next(
        dec
        for dec in task_ref.decorator_list
        if isinstance(dec, ast.Call) and getattr(dec.func, "id", "") == "dataclass"
    )
    assert {kw.arg: ast.literal_eval(kw.value) for kw in dataclass_decorator.keywords} == {
        "frozen": True,
        "slots": True,
        "init": False,
    }

    field_annotations = {
        stmt.target.id: ast.unparse(stmt.annotation)
        for stmt in task_ref.body
        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name)
    }
    assert field_annotations["mode"] == "AppMode"
    assert "AppMode | str" not in source.split("class TaskRef:", maxsplit=1)[1].split("def __init__", maxsplit=1)[0]

    overload_inits = [
        stmt
        for stmt in task_ref.body
        if isinstance(stmt, ast.FunctionDef)
        and stmt.name == "__init__"
        and any(getattr(dec, "id", "") == "overload" for dec in stmt.decorator_list)
    ]
    overload_mode_annotations = [
        ast.unparse(arg.annotation)
        for fn in overload_inits
        for arg in fn.args.kwonlyargs
        if arg.arg == "mode" and arg.annotation is not None
    ]
    assert overload_mode_annotations == ["AppMode", "str"]

    real_init = next(
        stmt
        for stmt in task_ref.body
        if isinstance(stmt, ast.FunctionDef)
        and stmt.name == "__init__"
        and not any(getattr(dec, "id", "") == "overload" for dec in stmt.decorator_list)
    )
    real_mode = next(arg for arg in real_init.args.kwonlyargs if arg.arg == "mode")
    assert ast.unparse(real_mode.annotation) == "AppMode | str"

    typing_import = next(node for node in tree.body if isinstance(node, ast.ImportFrom) and node.module == "typing")
    assert {alias.name for alias in typing_import.names} in (
        {"Final", "TypeVar", "cast", "overload"},
        {"Final", "cast", "overload"},
    )


def test_error_construction_is_strict_mypy_friendly() -> None:
    source = module_source()
    tree = ast.parse(source)
    has_typevar = "_E = TypeVar('_E', bound='ModeContractError')" in source or (
        '_E = TypeVar("_E", bound="ModeContractError")' in source
    )
    err_functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_err"]
    if err_functions:
        err_fn = err_functions[0]
        assert has_typevar
        assert ast.unparse(err_fn.args.args[0].annotation) == "type[_E]"
        assert ast.unparse(err_fn.returns) == "_E"
    else:
        assert "_err(" not in source


def test_app_mode_from_json_accepts_only_exact_builtin_personal_or_work() -> None:
    mod = contract()
    assert mod.app_mode_from_json("personal") is mod.AppMode.PERSONAL
    assert mod.app_mode_from_json("work") is mod.AppMode.WORK

    bad_values = ["js-agent", "js-work", "Personal", "WORK", "", None, True, 1, AlwaysEqual(), MyStr("work")]
    for value in bad_values:
        with pytest.raises(mod.ModeMappingError) as caught:
            mod.app_mode_from_json(value)
        assert_error(
            caught.value,
            code="invalid_value",
            field="mode",
            detail="mode must be personal or work",
        )


def test_direct_mode_coerce_accepts_exact_app_mode_but_not_other_enums_or_str_subclasses() -> None:
    mod = contract()

    class OtherStrEnum(mod.StrEnum):
        WORK = "work"

    assert make_direct(mod, mode=mod.AppMode.WORK).mode is mod.AppMode.WORK
    assert make_direct(mod, mode="work").mode is mod.AppMode.WORK

    for value in (OtherStrEnum.WORK, MyStr("work"), AlwaysEqual()):
        with pytest.raises(mod.ModeMappingError):
            make_direct(mod, mode=value)


def test_task_ref_subclassing_is_fail_closed_against_post_init_bypass() -> None:
    mod = contract()

    with pytest.raises(TypeError):

        class EvilTaskRef(mod.TaskRef):
            def __post_init__(self) -> None:
                return None

    with pytest.raises(TypeError):
        type(
            "DynamicEvilTaskRef",
            (mod.TaskRef,),
            {"__post_init__": lambda self: None},
        )

    assert make_direct(mod, mode="work").mode is mod.AppMode.WORK


def test_from_dict_rejects_app_mode_object_because_decoded_mode_must_be_builtin_str() -> None:
    mod = contract()
    with pytest.raises(mod.ModeMappingError):
        mod.TaskRef.from_dict(base_payload(mode=mod.AppMode.WORK))
    assert make_direct(mod, mode=mod.AppMode.WORK).mode is mod.AppMode.WORK


def test_product_id_from_mode_is_authoritative_and_exact() -> None:
    mod = contract()
    assert mod.product_id_from_mode(mod.AppMode.PERSONAL) == "js-agent"
    assert mod.product_id_from_mode("personal") == "js-agent"
    assert mod.product_id_from_mode(mod.AppMode.WORK) == "js-work"
    assert mod.product_id_from_mode("work") == "js-work"

    class OtherStrEnum(mod.StrEnum):
        WORK = "work"

    for value in ("js-agent", "js-work", MyStr("work"), OtherStrEnum.WORK, AlwaysEqual()):
        with pytest.raises(mod.ModeMappingError):
            mod.product_id_from_mode(value)


def test_mode_from_product_id_is_strict_compat_helper() -> None:
    mod = contract()
    assert mod.mode_from_product_id("js-agent") is mod.AppMode.PERSONAL
    assert mod.mode_from_product_id("js-work") is mod.AppMode.WORK

    for value in ("personal", "work", " js-work", "js-work ", "JS-WORK", "", None, True, 1, MyStr("js-work"), AlwaysEqual()):
        with pytest.raises(mod.ModeMappingError) as caught:
            mod.mode_from_product_id(value)
        assert "js-work " not in str(caught.value)
        assert "JS-WORK" not in str(caught.value)


def test_assert_mode_product_compatible_rejects_conflicts_and_bad_types() -> None:
    mod = contract()
    mod.assert_mode_product_compatible(mode="work", product_id="js-work")
    with pytest.raises(mod.ModeMappingError) as conflict:
        mod.assert_mode_product_compatible(mode="work", product_id="js-agent")
    assert_error(conflict.value, code="mode_product_conflict", field="product_id")

    for value in (None, True, 1, [], {}, MyStr("js-work")):
        with pytest.raises(mod.ModeMappingError) as caught:
            mod.assert_mode_product_compatible(mode="work", product_id=value)
        assert_error(caught.value, code="invalid_type", field="product_id", detail="product_id must be text")

    with pytest.raises(mod.ModeMappingError) as unknown:
        mod.assert_mode_product_compatible(mode="work", product_id="unknown-product")
    assert_error(unknown.value, code="invalid_value", field="product_id", detail="unknown legacy product_id")


def test_task_ref_from_dict_requires_exact_builtin_dict_root() -> None:
    mod = contract()

    class DictSubclass(dict[str, object]):
        pass

    class CustomMapping(Mapping[str, object]):
        def __iter__(self) -> Any:
            return iter(())

        def __len__(self) -> int:
            return 0

        def __getitem__(self, key: str) -> object:
            raise KeyError(key)

    for value in ([], (), "x", CustomMapping(), DictSubclass(base_payload())):
        with pytest.raises(mod.TaskRefValidationError) as caught:
            mod.TaskRef.from_dict(value)
        assert_error(caught.value, code="invalid_root", field=None)


def test_task_ref_from_dict_requires_exact_builtin_string_keys() -> None:
    mod = contract()
    for key in (1, MyStr("mode")):
        payload = {
            "schema_version": 1,
            key: "work",
            "owner": "owner-a",
            "session": "session-a",
            "run": "run-a",
            "workspace": "work-a",
        }
        with pytest.raises(mod.TaskRefValidationError) as caught:
            mod.TaskRef.from_dict(payload)
        assert_error(caught.value, code="invalid_key", field=None)
        assert "1" not in caught.value.detail


def test_task_ref_unknown_fields_do_not_echo_key_or_secret() -> None:
    mod = contract()
    for key in ("aaa_extra", "secret-token-sk-should-not-echo", "bad\nlog", "bad\x00key"):
        payload = base_payload()
        payload[key] = "sentinel-secret-value"
        with pytest.raises(mod.UnknownFieldError) as caught:
            mod.TaskRef.from_dict(payload)
        assert_error(
            caught.value,
            code="unknown_field",
            field=None,
            detail="TaskRef payload contains unknown fields",
        )
        rendered = f"{caught.value} {caught.value.field} {caught.value.detail}"
        assert key not in rendered
        assert "secret-token" not in rendered
        assert "sentinel-secret-value" not in rendered
        assert repr(payload) not in rendered


def test_task_ref_rejects_product_and_product_id_even_when_matching_mode() -> None:
    mod = contract()
    for aliases in (
        {"product_id": "js-work"},
        {"product": "js-work"},
        {"product": "js-work", "product_id": "js-work"},
    ):
        with pytest.raises(mod.UnknownFieldError) as caught:
            mod.TaskRef.from_dict(base_payload(**aliases))
        assert_error(caught.value, code="unknown_field", field=None)
        assert "product" not in str(caught.value)


def test_task_ref_requires_all_canonical_fields_in_schema_order() -> None:
    mod = contract()
    fields = ["schema_version", "mode", "owner", "session", "run", "workspace"]
    for field in fields:
        payload = base_payload()
        payload.pop(field)
        with pytest.raises(mod.TaskRefValidationError) as caught:
            mod.TaskRef.from_dict(payload)
        assert_error(caught.value, code="missing_field", field=field, detail="missing TaskRef field")

    payload = base_payload()
    payload.pop("owner")
    payload.pop("run")
    with pytest.raises(mod.TaskRefValidationError) as caught:
        mod.TaskRef.from_dict(payload)
    assert caught.value.field == "owner"


def test_task_ref_schema_version_must_be_exact_builtin_int_one() -> None:
    mod = contract()
    assert mod.TaskRef.from_dict(base_payload(schema_version=1)).to_dict()["schema_version"] == 1
    for value in (True, 1.0, "1", 0, 2, None, Decimal("1"), Fraction(1, 1), AlwaysEqual()):
        with pytest.raises(mod.TaskRefValidationError) as caught:
            mod.TaskRef.from_dict(base_payload(schema_version=value))
        assert_error(
            caught.value,
            code="invalid_type",
            field="schema_version",
            detail="schema_version must be 1",
        )


def test_from_dict_casts_shared_fields_to_constructor_instead_of_prechecking_scalar_types() -> None:
    mod = contract()
    source = module_source()
    assert "_require_decoded_json_scalar_types" not in source
    assert 'owner=cast(str, data["owner"])' in source
    assert 'session=cast(str, data["session"])' in source
    assert 'run=cast(str, data["run"])' in source
    assert 'workspace=cast(str | None, data["workspace"])' in source

    for field, value in {"owner": True, "session": 1, "run": [], "workspace": True}.items():
        with pytest.raises(mod.TaskRefValidationError) as from_dict_error:
            mod.TaskRef.from_dict(base_payload(**{field: value}))
        with pytest.raises(mod.TaskRefValidationError) as direct_error:
            make_direct(mod, **{field: value})
        assert type(from_dict_error.value) is type(direct_error.value)
        assert from_dict_error.value.code == direct_error.value.code
        assert from_dict_error.value.field == direct_error.value.field
        assert from_dict_error.value.detail == direct_error.value.detail


@pytest.mark.parametrize(
    ("overrides", "direct_overrides"),
    [
        ({"mode": "js-work"}, {"mode": "js-work"}),
        ({"mode": "WORK"}, {"mode": "WORK"}),
        ({"owner": True}, {"owner": True}),
        ({"owner": "owner/a"}, {"owner": "owner/a"}),
        ({"owner": " owner"}, {"owner": " owner"}),
        ({"session": 1}, {"session": 1}),
        ({"session": r"session\bad"}, {"session": r"session\bad"}),
        ({"run": []}, {"run": []}),
        ({"run": "run<bad"}, {"run": "run<bad"}),
        ({"workspace": True}, {"workspace": True}),
        ({"workspace": "team:alpha"}, {"workspace": "team:alpha"}),
        ({"workspace": None}, {"workspace": None}),
        ({"mode": "personal", "workspace": "work-a"}, {"mode": "personal", "workspace": "work-a"}),
    ],
)
def test_direct_and_from_dict_shared_field_errors_are_identical_except_decoded_app_mode(
    overrides: dict[str, object],
    direct_overrides: dict[str, object],
) -> None:
    mod = contract()
    with pytest.raises(mod.ModeContractError) as direct_error:
        make_direct(mod, **direct_overrides)
    with pytest.raises(mod.ModeContractError) as from_dict_error:
        mod.TaskRef.from_dict(base_payload(**overrides))
    assert type(direct_error.value) is type(from_dict_error.value)
    assert direct_error.value.code == from_dict_error.value.code
    assert direct_error.value.field == from_dict_error.value.field
    assert direct_error.value.detail == from_dict_error.value.detail


def test_from_dict_multi_error_order_unknown_wins_before_missing_schema_mode_and_field_types() -> None:
    mod = contract()
    payload = {
        "schema_version": 2,
        "mode": "bad",
        "session": 1,
        "run": "run-a",
        "workspace": "work-a",
        "secret-token-sk-should-not-echo": "secret",
    }
    with pytest.raises(mod.UnknownFieldError) as caught:
        mod.TaskRef.from_dict(payload)
    assert_error(caught.value, code="unknown_field", field=None)
    assert "secret-token" not in str(caught.value)


def test_from_dict_multi_error_order_missing_wins_before_schema_mode_and_field_types() -> None:
    mod = contract()
    payload = base_payload(schema_version=2, mode="bad", session=1)
    payload.pop("owner")
    with pytest.raises(mod.TaskRefValidationError) as caught:
        mod.TaskRef.from_dict(payload)
    assert_error(caught.value, code="missing_field", field="owner")


def test_from_dict_multi_error_order_schema_wins_before_mode_and_shared_field_validation() -> None:
    mod = contract()
    with pytest.raises(mod.TaskRefValidationError) as caught:
        mod.TaskRef.from_dict(base_payload(schema_version=1.0, mode="bad-mode", owner=True, workspace="bad:path"))
    assert_error(
        caught.value,
        code="invalid_type",
        field="schema_version",
        detail="schema_version must be 1",
    )


def test_from_dict_multi_error_order_mode_wins_before_shared_field_validation() -> None:
    mod = contract()
    with pytest.raises(mod.ModeMappingError) as caught:
        mod.TaskRef.from_dict(base_payload(mode="bad-mode", owner=True, session=1, run=[], workspace=True))
    assert_error(
        caught.value,
        code="invalid_value",
        field="mode",
        detail="mode must be personal or work",
    )


def test_post_init_shared_field_order_owner_session_run_workspace() -> None:
    mod = contract()
    bad = {"owner": True, "session": 1, "run": [], "workspace": True}
    for factory in (lambda: make_direct(mod, **bad), lambda: mod.TaskRef.from_dict(base_payload(**bad))):
        with pytest.raises(mod.TaskRefValidationError) as caught:
            factory()
        assert_error(caught.value, code="invalid_type", field="owner", detail="owner must be text")


def test_owner_uses_owner_specific_grammar_and_length() -> None:
    mod = contract()
    assert make_direct(mod, owner="o").owner == "o"
    assert make_direct(mod, owner="a" * 192).owner == "a" * 192
    for value in ("", " owner", "owner ", "a" * 193, "owner/a", "_owner", "-owner", "owner@example", "拥有者", "own\x00er", "e\u0301"):
        with pytest.raises(mod.TaskRefValidationError):
            make_direct(mod, owner=value)


def test_session_uses_session_specific_grammar_and_length() -> None:
    mod = contract()
    assert make_direct(mod, session="s").session == "s"
    assert make_direct(mod, session="session/a:b-1_2.3").session == "session/a:b-1_2.3"
    assert make_direct(mod, session="a" * 192).session == "a" * 192
    for value in ("", " session", "session ", "a" * 193, r"session\bad", 'session"bad', "session<bad", "s\x00", "会话", "e\u0301", "_session"):
        with pytest.raises(mod.TaskRefValidationError):
            make_direct(mod, session=value)


def test_run_uses_run_specific_grammar_and_length() -> None:
    mod = contract()
    assert make_direct(mod, run="r").run == "r"
    assert make_direct(mod, run="run/a:b-1_2.3").run == "run/a:b-1_2.3"
    assert make_direct(mod, run="a" * 192).run == "a" * 192
    for value in ("", " run", "run ", "a" * 193, r"run\bad", 'run"bad', "run<bad", "r\x00", "运行", "e\u0301", "_run"):
        with pytest.raises(mod.TaskRefValidationError):
            make_direct(mod, run=value)


def test_personal_task_ref_requires_null_workspace() -> None:
    mod = contract()
    assert make_direct(mod, mode="personal", workspace=None).workspace is None
    for value in ("", "work-default", " ", "team.alpha_01"):
        with pytest.raises(mod.TaskRefValidationError) as caught:
            make_direct(mod, mode="personal", workspace=value)
        assert_error(
            caught.value,
            code="workspace_mode_mismatch",
            field="workspace",
            detail="personal workspace must be null",
        )


def test_work_workspace_accepts_only_v1_opaque_handle_without_colon() -> None:
    mod = contract()
    for value in ("w", "work-default", "team.alpha_01", "a" * 128):
        assert make_direct(mod, workspace=value).workspace == value
    with pytest.raises(mod.TaskRefValidationError) as none_error:
        make_direct(mod, workspace=None)
    assert_error(
        none_error.value,
        code="workspace_mode_mismatch",
        field="workspace",
        detail="work workspace must be non-empty",
    )
    for value in ("", " ", "a" * 129, "team:alpha"):
        with pytest.raises(mod.TaskRefValidationError) as caught:
            make_direct(mod, workspace=value)
        if value == "":
            assert_error(caught.value, code="workspace_mode_mismatch", field="workspace")
        else:
            assert_error(caught.value, code="invalid_value", field="workspace", detail="workspace must be an opaque handle")


def test_work_workspace_rejects_paths_uri_drive_and_dot_shapes() -> None:
    mod = contract()
    for value in (
        "/tmp/work",
        "//server/share",
        "a/b",
        "../x",
        ".",
        "..",
        "~",
        "~/x",
        "file:///tmp/x",
        "workspace:abc",
        r"C:\work",
        "C:/work",
        "C:work",
    ):
        with pytest.raises(mod.TaskRefValidationError) as caught:
            make_direct(mod, workspace=value)
        assert_error(caught.value, code="invalid_value", field="workspace", detail="workspace must be an opaque handle")


def test_task_ref_to_dict_has_schema_version_and_no_legacy_product() -> None:
    mod = contract()
    ref = make_direct(mod)
    assert ref.to_dict() == {
        "schema_version": 1,
        "mode": "work",
        "owner": "owner-a",
        "session": "session-a",
        "run": "run-a",
        "workspace": "work-a",
    }
    assert "product" not in ref.to_dict()
    assert "product_id" not in ref.to_dict()


def test_task_ref_canonical_bytes_are_unique_rfc8785_identity() -> None:
    mod = contract()
    ref = mod.TaskRef.from_dict(
        {
            "workspace": "work-a",
            "run": "run-a",
            "session": "session-a",
            "owner": "owner-a",
            "mode": "work",
            "schema_version": 1,
        }
    )
    canonical = ref.canonical_bytes()
    assert canonical == b'{"mode":"work","owner":"owner-a","run":"run-a","schema_version":1,"session":"session-a","workspace":"work-a"}'
    assert b"schema_version" in canonical
    assert b"product" not in canonical
    assert ref.canonical_bytes() == canonical


def test_task_ref_canonical_hash_uses_hardcoded_domain_and_nul_separator() -> None:
    mod = contract()
    ref = make_direct(mod)
    assert mod.TASK_REF_HASH_DOMAIN == b"js-agent:task-ref:v1\0"
    expected = "sha256:" + hashlib.sha256(
        b"js-agent:task-ref:v1\0" + ref.canonical_bytes()
    ).hexdigest()
    assert ref.canonical_hash() == expected
    assert ref.canonical_hash() != "sha256:" + hashlib.sha256(ref.canonical_bytes()).hexdigest()
    assert list(inspect.signature(mod.TaskRef.canonical_hash).parameters) == ["self"]


def test_task_ref_is_frozen_slots_and_hash_not_affected_by_input_mutation() -> None:
    mod = contract()
    payload = base_payload()
    ref = mod.TaskRef.from_dict(payload)
    first_hash = ref.canonical_hash()
    payload["owner"] = "owner-b"
    assert ref.owner == "owner-a"
    assert ref.canonical_hash() == first_hash
    with pytest.raises(FrozenInstanceError):
        ref.owner = "owner-b"
    assert hasattr(ref, "__dict__") is False


def test_contract_errors_are_read_only_and_do_not_echo_values_or_payloads() -> None:
    mod = contract()
    payload = base_payload(owner="sentinel/owner-secret")
    with pytest.raises(mod.TaskRefValidationError) as caught:
        mod.TaskRef.from_dict(payload)
    rendered = f"{caught.value} {caught.value.field} {caught.value.detail}"
    assert "sentinel-owner-secret" not in rendered
    assert repr(payload) not in rendered
    for attr in ("code", "field", "detail"):
        with pytest.raises(AttributeError):
            setattr(caught.value, attr, "x")


def test_mode_contract_imports_only_allowlisted_modules() -> None:
    tree = module_tree()
    allowed_imports = {
        ("__future__", ("annotations",)),
        ("dataclasses", ("dataclass",)),
        ("enum", ("StrEnum",)),
        ("typing", ("Final", "TypeVar", "cast", "overload")),
        ("typing", ("Final", "cast", "overload")),
        ("js.echo.primitives", ("canonical_json_bytes",)),
    }
    allowed_plain_imports = {"hashlib", "re", "unicodedata"}
    forbidden_roots = {
        "pathlib",
        "os",
        "io",
        "socket",
        "urllib",
        "subprocess",
        "importlib",
        "js.config",
        "js.web",
        "js_work",
        "js.tools",
        "js.security",
        "js.models",
        "js.agent",
        "js.appshell",
        "js.echo.turn_context",
        "js.echo.turn_runtime",
        "js.echo.ledger",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = tuple(alias.name for alias in node.names)
            assert set(names) <= allowed_plain_imports
            assert not any(name in forbidden_roots for name in names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0
            assert all(alias.name != "*" for alias in node.names)
            assert (node.module, tuple(alias.name for alias in node.names)) in allowed_imports
            assert node.module not in forbidden_roots


STRICT_ALLOWED_CALL_SHAPES = {
    "AppMode",
    "ClientTaskRequestV1",
    "ClientTaskRequestValidationError",
    "DirectoryGrantValidationError",
    "DirectoryGrantV1",
    "ArtifactRefValidationError",
    "ArtifactRefV1",
    "AttentionItemValidationError",
    "AttentionItemV1",
    "ConnectionRefValidationError",
    "ConnectionRefV1",
    "ConnectorManifestValidationError",
    "ConnectorManifestV1",
    "ModeManifestValidationError",
    "ModeManifestV1",
    "ModeMappingError",
    "TaskRef",
    "TaskRefValidationError",
    "TaskAuthorityError",
    "TypeError",
    "UnknownFieldError",
    "_coerce_app_mode",
    "_artifact_error",
    "_artifact_dict",
    "_artifact_schema",
    "_attention_error",
    "_attention_dict",
    "_connection_error",
    "_connection_dict",
    "_connector_error",
    "_connector_dict",
    "_grant_dict",
    "_grant_error",
    "_grant_root",
    "_manifest_dict",
    "_manifest_error",
    "_manifest_ids",
    "_manifest_schema",
    "_validate_digest",
    "_validate_id_list",
    "_MODE_MANIFEST_ID_RE.fullmatch",
    "_DIRECTORY_GRANT_ROOT_RE.fullmatch",
    "_DIGEST_RE.fullmatch",
    "_ARTIFACT_URI_RE.fullmatch",
    "_require_exact_dict",
    "_require_exact_text",
    "_validate_identity",
    "_validate_schema_version",
    "_validate_workspace",
    "_WORKSPACE_RE.fullmatch",
    "any",
    "app_mode_from_json",
    "canonical_json_bytes",
    "cast",
    "cls",
    "dataclass",
    "frozenset",
    "hashlib.sha256",
    "len",
    "list",
    "item.strip",
    "object.__setattr__",
    "pattern.fullmatch",
    "product_id_from_mode",
    "re.compile",
    "self.__post_init__",
    "self._check_operand",
    "self.canonical_bytes",
    "self.to_dict",
    "self.root.startswith",
    "self.root.split",
    "other.root.rstrip",
    "other.root.split",
    "set",
    "set.intersection",
    "set.issubset",
    "sorted",
    "super",
    "str.startswith",
    "text.strip",
    "tuple",
    "type",
    "unicodedata.category",
    "unicodedata.normalize",
    "value.strip",
    "value.split",
    "value.startswith",
    "value.endswith",
}
LOCAL_RECEIVER_ROOTS = {"pattern", "self", "text", "value", "item", "result", "cls", "other"}
STRUCTURAL_EXTRA_CALL_SHAPES = {
    "CALL.__init__",
    "CALL.hexdigest",
    "CALL.startswith",
    "CALL.issubset",
    "CALL.intersection",
    "getattr",
    "isinstance",
    "result.append",
}
EXACT_STRUCTURAL_CONSTANT_VALUES = {
    "_TASK_REF_FIELDS": {"schema_version", "mode", "owner", "session", "run", "workspace"},
    "_TASK_REF_ORDER": ("schema_version", "mode", "owner", "session", "run", "workspace"),
    "_CLIENT_TASK_REQUEST_FIELDS": {"mode", "session", "workspace"},
    "_MODE_MANIFEST_FIELDS": {
        "schema_version",
        "mode",
        "feature_ids",
        "tool_ids",
        "connector_ids",
        "workspace_required",
    },
    "_MODE_MANIFEST_FIELD_ORDER": (
        "schema_version",
        "mode",
        "feature_ids",
        "tool_ids",
        "connector_ids",
        "workspace_required",
    ),
    "_DIRECTORY_GRANT_FIELDS": {"schema_version", "mode", "workspace", "root"},
    "_DIRECTORY_GRANT_FIELD_ORDER": ("schema_version", "mode", "workspace", "root"),
    "_ATTENTION_ITEM_FIELDS": {
        "schema_version", "kind", "mode", "owner", "session", "run",
        "workspace", "effect_digest", "args_digest", "eligible_approver", "ttl_seconds",
    },
    "_ATTENTION_ITEM_FIELD_ORDER": (
        "schema_version", "kind", "mode", "owner", "session", "run",
        "workspace", "effect_digest", "args_digest", "eligible_approver", "ttl_seconds",
    ),
    "_ARTIFACT_REF_FIELDS": {
        "schema_version", "mode", "owner", "session", "workspace", "kind", "uri", "digest", "acl", "created_by_run",
    },
    "_ARTIFACT_REF_FIELD_ORDER": (
        "schema_version", "mode", "owner", "session", "workspace", "kind", "uri", "digest", "acl", "created_by_run",
    ),
    "_CONNECTOR_MANIFEST_FIELDS": {
        "schema_version", "connector_type", "capabilities", "read_scopes", "write_scopes", "approval_policy",
    },
    "_CONNECTOR_MANIFEST_FIELD_ORDER": (
        "schema_version", "connector_type", "capabilities", "read_scopes", "write_scopes", "approval_policy",
    ),
    "_CONNECTION_REF_FIELDS": {
        "schema_version", "mode", "owner", "workspace", "connector_type", "connection_id", "authorized_by",
    },
    "_CONNECTION_REF_FIELD_ORDER": (
        "schema_version", "mode", "owner", "workspace", "connector_type", "connection_id", "authorized_by",
    ),
}


def call_shape_root(shape: str) -> str:
    return shape.split(".", maxsplit=1)[0]


def canonical_security_sensitive_bindings() -> set[str]:
    """Derive compare-only authority types and structural field constants."""
    tree = module_tree()
    class_names = {node.name for node in tree.body if isinstance(node, ast.ClassDef)}
    protected = {
        node.target.id
        for node in tree.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id.endswith(("_FIELDS", "_ORDER"))
    }
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare) or not any(isinstance(op, (ast.Is, ast.IsNot)) for op in node.ops):
            continue
        for operand in (node.left, *node.comparators):
            if isinstance(operand, ast.Name) and operand.id in class_names:
                protected.add(operand.id)
    return protected


def derived_protected_roots_and_attrs() -> tuple[set[str], set[str]]:
    roots: set[str] = set()
    attrs: set[str] = set()
    for shape in STRICT_ALLOWED_CALL_SHAPES:
        root = call_shape_root(shape)
        if "." in shape:
            attrs.add(shape)
        if root in LOCAL_RECEIVER_ROOTS or root == "CALL":
            continue
        roots.add(root)
    roots.update(canonical_security_sensitive_bindings())
    return roots, attrs


def io_dynamic_call_offenders(source: str) -> list[str]:

    def call_shape(expr: ast.AST) -> str:
        if isinstance(expr, ast.Name):
            return expr.id
        if isinstance(expr, ast.Attribute):
            if isinstance(expr.value, ast.Call) and expr.attr in {"__init__", "hexdigest", "startswith", "issubset", "intersection"}:
                return f"CALL.{expr.attr}"
            base = call_shape(expr.value)
            if base == "<dynamic>":
                return "<dynamic>"
            return f"{base}.{expr.attr}"
        return "<dynamic>"

    offenders: list[str] = []
    tree = ast.parse(source)
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent

    def function_params(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
        params = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
        if fn.args.vararg is not None:
            params.append(fn.args.vararg)
        if fn.args.kwarg is not None:
            params.append(fn.args.kwarg)
        return {param.arg for param in params}

    def is_shadowed_call_name(node: ast.AST, name: str) -> bool:
        parent = parents.get(node)
        while parent is not None:
            if isinstance(parent, ast.FunctionDef | ast.AsyncFunctionDef):
                return name in function_params(parent)
            parent = parents.get(parent)
        return False

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            shape = call_shape(node.func)
            if shape not in STRICT_ALLOWED_CALL_SHAPES and shape not in STRUCTURAL_EXTRA_CALL_SHAPES:
                if shape == "open" and not is_shadowed_call_name(node, "open"):
                    offenders.append("open")
                else:
                    offenders.append(f"disallowed_call_shape:{shape}")
    return offenders


def protected_binding_offenders(source: str) -> list[str]:
    protected_roots, protected_attrs = derived_protected_roots_and_attrs()
    legal_top_level_defs = {
        "AppMode",
        "ClientTaskRequestV1",
        "ClientTaskRequestValidationError",
        "DirectoryGrantValidationError",
        "DirectoryGrantV1",
        "ArtifactRefValidationError",
        "ArtifactRefV1",
        "AttentionItemValidationError",
        "AttentionItemV1",
        "ConnectionRefValidationError",
        "ConnectionRefV1",
        "ConnectorManifestValidationError",
        "ConnectorManifestV1",
        "ModeManifestValidationError",
        "ModeManifestV1",
        "ModeMappingError",
        "ResolvedTaskAuthorityV1",
        "TaskRef",
        "TaskRefValidationError",
        "TaskAuthorityError",
        "UnknownFieldError",
        "_coerce_app_mode",
        "_artifact_error",
        "_artifact_dict",
        "_artifact_schema",
        "_attention_error",
        "_attention_dict",
        "_connection_error",
        "_connection_dict",
        "_connector_error",
        "_connector_dict",
        "_grant_dict",
        "_grant_error",
        "_grant_root",
        "_manifest_dict",
        "_manifest_error",
        "_manifest_ids",
        "_manifest_schema",
        "_validate_digest",
        "_validate_id_list",
        "_require_exact_dict",
        "_require_exact_text",
        "_validate_identity",
        "_validate_schema_version",
        "_validate_workspace",
        "app_mode_from_json",
        "assert_mode_product_compatible",
        "mode_from_product_id",
        "product_id_from_mode",
        "task_ref_from_client_request_v1",
    }
    legal_top_level_defs.update(canonical_security_sensitive_bindings())
    legal_top_level_imports = {
        ("dataclasses", "dataclass", "dataclass"),
        ("enum", "StrEnum", "StrEnum"),
        ("hashlib", "hashlib", "hashlib"),
        ("js.echo.primitives", "canonical_json_bytes", "canonical_json_bytes"),
        ("re", "re", "re"),
        ("typing", "Final", "Final"),
        ("typing", "cast", "cast"),
        ("typing", "overload", "overload"),
        ("unicodedata", "unicodedata", "unicodedata"),
    }

    def target_names(target: ast.AST) -> list[str]:
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, ast.Attribute):
            roots = target_names(target.value)
            if not roots:
                return []
            return [f"{root}.{target.attr}" for root in roots]
        if isinstance(target, ast.Starred):
            return target_names(target.value)
        if isinstance(target, ast.Tuple | ast.List):
            names: list[str] = []
            for element in target.elts:
                names.extend(target_names(element))
            return names
        return []

    def is_protected(name: str) -> bool:
        root = name.split(".", maxsplit=1)[0]
        return name in protected_attrs or root in protected_roots

    def append_target_offenders(target: ast.AST, offenders: list[str]) -> None:
        for name in target_names(target):
            if is_protected(name):
                offenders.append(f"protected_binding:{name}")

    def call_shape(expr: ast.AST) -> str:
        if isinstance(expr, ast.Name):
            return expr.id
        if isinstance(expr, ast.Attribute):
            base = call_shape(expr.value)
            if base == "<dynamic>":
                return "<dynamic>"
            return f"{base}.{expr.attr}"
        if isinstance(expr, ast.Call):
            return call_shape(expr.func)
        return "<dynamic>"

    def is_exact_legal_top_level_assignment(node: ast.Assign | ast.AnnAssign | ast.AugAssign | ast.NamedExpr) -> bool:
        if not is_top_level(node):
            return False
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            target = node.target
            value = node.value
        else:
            return False
        if (
            isinstance(target, ast.Name)
            and target.id in ("_WORKSPACE_RE", "_MODE_MANIFEST_ID_RE", "_DIRECTORY_GRANT_ROOT_RE", "_DIGEST_RE", "_ARTIFACT_URI_RE")
            and isinstance(value, ast.Call)
            and call_shape(value.func) == "re.compile"
        ):
            return True
        if not isinstance(target, ast.Name) or target.id not in EXACT_STRUCTURAL_CONSTANT_VALUES:
            return False
        expected = EXACT_STRUCTURAL_CONSTANT_VALUES[target.id]
        if isinstance(expected, set):
            if (
                not isinstance(value, ast.Call)
                or call_shape(value.func) != "frozenset"
                or len(value.args) != 1
                or value.keywords
            ):
                return False
            value = value.args[0]
        try:
            return ast.literal_eval(value) == expected
        except (TypeError, ValueError):
            return False

    def function_params(fn: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> list[ast.arg]:
        params = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
        if fn.args.vararg is not None:
            params.append(fn.args.vararg)
        if fn.args.kwarg is not None:
            params.append(fn.args.kwarg)
        return params

    tree = ast.parse(source)
    offenders: list[str] = []
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child._parent = parent  # type: ignore[attr-defined]

    def is_top_level(node: ast.AST) -> bool:
        return isinstance(getattr(node, "_parent", None), ast.Module)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".", maxsplit=1)[0]
                if (
                    is_protected(bound)
                    and not (is_top_level(node) and (alias.name, alias.name, bound) in legal_top_level_imports)
                ):
                    offenders.append(f"protected_binding:{bound}")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                bound = alias.asname or alias.name
                if (
                    is_protected(bound)
                    and not (is_top_level(node) and (module, alias.name, bound) in legal_top_level_imports)
                ):
                    offenders.append(f"protected_binding:{bound}")
        elif isinstance(node, ast.Assign):
            if not is_exact_legal_top_level_assignment(node):
                for target in node.targets:
                    append_target_offenders(target, offenders)
        elif isinstance(node, ast.AnnAssign | ast.AugAssign | ast.NamedExpr):
            if not is_exact_legal_top_level_assignment(node):
                append_target_offenders(node.target, offenders)
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                append_target_offenders(target, offenders)
        elif isinstance(node, ast.For | ast.AsyncFor | ast.comprehension):
            append_target_offenders(node.target, offenders)
        elif isinstance(node, ast.With | ast.AsyncWith):
            for item in node.items:
                if item.optional_vars is not None:
                    append_target_offenders(item.optional_vars, offenders)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            if not (is_top_level(node) and node.name in legal_top_level_defs) and is_protected(node.name):
                offenders.append(f"protected_binding:{node.name}")
            for param in function_params(node):
                if is_protected(param.arg):
                    offenders.append(f"protected_binding:{param.arg}")
        elif isinstance(node, ast.Lambda):
            for param in function_params(node):
                if is_protected(param.arg):
                    offenders.append(f"protected_binding:{param.arg}")
        elif (
            isinstance(node, ast.ClassDef)
            and not (is_top_level(node) and node.name in legal_top_level_defs)
            and is_protected(node.name)
        ):
            offenders.append(f"protected_binding:{node.name}")
    return offenders



def test_no_io_dynamic_call_helper_catches_alias_and_getattr_mutations() -> None:
    assert io_dynamic_call_offenders("open('x')") == ["open"]
    assert io_dynamic_call_offenders("reader = open\nreader('x')") == ["disallowed_call_shape:reader"]
    assert io_dynamic_call_offenders("reader: object = open\nreader('x')") == ["disallowed_call_shape:reader"]
    assert io_dynamic_call_offenders("a = open\nb = a\nb('x')") == ["disallowed_call_shape:b"]
    assert io_dynamic_call_offenders("__builtins__['open']('x')") == ["disallowed_call_shape:<dynamic>"]
    assert io_dynamic_call_offenders("getattr(__builtins__, 'open')('x')") == ["disallowed_call_shape:<dynamic>"]
    assert io_dynamic_call_offenders("reader = getattr(__builtins__, 'open')\nreader('x')") == [
        "disallowed_call_shape:reader"
    ]
    assert io_dynamic_call_offenders("reader = open\nreader = canonical_json_bytes\nreader({})") == [
        "disallowed_call_shape:reader"
    ]
    assert io_dynamic_call_offenders("def f(open):\n    open('x')") == ["disallowed_call_shape:open"]


def test_no_io_structural_helper_allows_current_leaf_and_plain_legal_snippet() -> None:
    legal_leaf_snippet = """
import re

from js.echo.primitives import canonical_json_bytes

_RE = re.compile("x")


def encode(value: str) -> bytes:
    return canonical_json_bytes({"length": len(value)})
"""
    assert io_dynamic_call_offenders(legal_leaf_snippet) == []
    assert protected_binding_offenders(legal_leaf_snippet) == []
    assert io_dynamic_call_offenders(module_source()) == []
    assert protected_binding_offenders(module_source()) == []


def test_no_io_protected_binding_integrity_rejects_allowed_call_root_rebinding() -> None:
    assert protected_binding_offenders("pattern.fullmatch = open\npattern.fullmatch('x')") == [
        "protected_binding:pattern.fullmatch"
    ]
    assert protected_binding_offenders("self.to_dict = open\nself.to_dict()") == [
        "protected_binding:self.to_dict"
    ]
    assert protected_binding_offenders("text.strip = open\ntext.strip()") == [
        "protected_binding:text.strip"
    ]
    assert protected_binding_offenders("value.strip = open\nvalue.strip()") == [
        "protected_binding:value.strip"
    ]
    assert protected_binding_offenders("_coerce_app_mode = open\n_coerce_app_mode('work')") == [
        "protected_binding:_coerce_app_mode"
    ]
    assert protected_binding_offenders("any = open\nany([])") == ["protected_binding:any"]
    assert protected_binding_offenders("def f(_validate_workspace):\n    return _validate_workspace(None)") == [
        "protected_binding:_validate_workspace"
    ]
    assert protected_binding_offenders("def f():\n    _validate_workspace = open\n    return _validate_workspace(None)") == [
        "protected_binding:_validate_workspace"
    ]
    assert protected_binding_offenders("[x for _validate_workspace in items]") == [
        "protected_binding:_validate_workspace"
    ]
    assert protected_binding_offenders("canonical_json_bytes = open\ncanonical_json_bytes('x')") == [
        "protected_binding:canonical_json_bytes"
    ]
    assert protected_binding_offenders("hashlib.sha256 = open\nhashlib.sha256('x')") == [
        "protected_binding:hashlib.sha256"
    ]
    assert protected_binding_offenders("def f(canonical_json_bytes):\n    return canonical_json_bytes({})") == [
        "protected_binding:canonical_json_bytes"
    ]
    assert protected_binding_offenders("def f():\n    canonical_json_bytes = open\n    return canonical_json_bytes('x')") == [
        "protected_binding:canonical_json_bytes"
    ]
    assert protected_binding_offenders("canonical_json_bytes: object = open") == [
        "protected_binding:canonical_json_bytes"
    ]
    assert protected_binding_offenders("del canonical_json_bytes") == ["protected_binding:canonical_json_bytes"]
    assert protected_binding_offenders("[x for canonical_json_bytes in items]") == [
        "protected_binding:canonical_json_bytes"
    ]


def test_no_io_protected_binding_integrity_covers_authority_guards_and_field_allowlists() -> None:
    assert protected_binding_offenders(
        "_CLIENT_TASK_REQUEST_FIELDS = frozenset({'mode', 'session', 'workspace', 'owner'})"
    ) == ["protected_binding:_CLIENT_TASK_REQUEST_FIELDS"]
    assert protected_binding_offenders("ResolvedTaskAuthorityV1 = ClientTaskRequestV1") == [
        "protected_binding:ResolvedTaskAuthorityV1"
    ]
    assert protected_binding_offenders(
        "def f(authority):\n    ResolvedTaskAuthorityV1 = type(authority)\n    return ResolvedTaskAuthorityV1"
    ) == ["protected_binding:ResolvedTaskAuthorityV1"]


def test_no_io_protected_roots_are_derived_from_shared_allowed_call_shapes() -> None:
    protected_roots, protected_attrs = derived_protected_roots_and_attrs()
    for shape in STRICT_ALLOWED_CALL_SHAPES:
        root = call_shape_root(shape)
        if root in LOCAL_RECEIVER_ROOTS or root == "CALL":
            continue
        assert root in protected_roots
        if "." in shape:
            assert shape in protected_attrs


def test_mode_contract_has_no_io_path_env_network_console_or_dynamic_calls() -> None:
    assert io_dynamic_call_offenders(module_source()) == []
    assert protected_binding_offenders(module_source()) == []


def mode_contract_reference_offenders_for_source(path: Path, source: str) -> list[str]:
    """Enforce Batch1's strict zero-reference policy without simulating Python execution."""
    target_module = "js.echo.mode_contract"
    tree = ast.parse(source)

    def module_name_for_path(source_path: Path) -> str:
        return ".".join(source_path.relative_to(ROOT).with_suffix("").parts)

    def package_name_for_path(source_path: Path) -> str:
        return ".".join(module_name_for_path(source_path).split(".")[:-1])

    def resolve_from_module(source_path: Path, *, level: int, module: str | None) -> str:
        if level == 0:
            return module or ""
        package_parts = package_name_for_path(source_path).split(".")
        anchor_parts = package_parts[: len(package_parts) - (level - 1)]
        if module:
            anchor_parts.extend(module.split("."))
        return ".".join(anchor_parts)

    def folded_string(node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and type(node.value) is str:
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = folded_string(node.left)
            right = folded_string(node.right)
            if left is not None and right is not None:
                return left + right
        return None

    found = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found = found or any(alias.name == target_module for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            resolved_module = resolve_from_module(path, level=node.level, module=node.module)
            imported_names = {alias.name for alias in node.names}
            found = found or resolved_module == target_module
            found = found or (
                f"{resolved_module}.mode_contract" == target_module
                and "mode_contract" in imported_names
            )
        found = found or folded_string(node) == target_module
    return [str(path)] if found else []


def test_no_callsite_batch1_strict_zero_reference_policy_is_fail_closed() -> None:
    path = ROOT / "js" / "echo" / "x.py"
    assert mode_contract_reference_offenders_for_source(path, "TARGET = 'js.echo.mode_contract'")
    assert mode_contract_reference_offenders_for_source(path, "print('js.echo.mode_contract')")
    assert mode_contract_reference_offenders_for_source(path, "TARGET = 'js.echo.' + 'mode_contract'")


def test_no_callsite_batch1_strict_zero_reference_policy_is_bounded_and_deduplicated() -> None:
    path = ROOT / "js" / "echo" / "ledger" / "probe.py"
    assert mode_contract_reference_offenders_for_source(
        path,
        "from ..mode_contract import TaskRef\nTARGET = 'js.echo.mode_contract'",
    ) == [str(path)]
    assert mode_contract_reference_offenders_for_source(
        path,
        "from ..not_mode_contract import TaskRef\nTARGET = 'js.echo.other'",
    ) == []
    assert mode_contract_reference_offenders_for_source(
        ROOT / "js" / "echo" / "x.py",
        "from . import mode_contract",
    )
    with pytest.raises(SyntaxError):
        mode_contract_reference_offenders_for_source(path, "def broken(")


def test_mode_contract_is_not_imported_by_existing_production_modules_in_batch1() -> None:
    production_roots = [ROOT / "js", ROOT / "js_work"]
    task4_projection_consumers = {
        "js/agent/tool_executor.py",
        "js/appshell/routers.py",
        "js/echo/ledger/effects.py",
        "js/echo/ledger/partition_retention.py",
        "js/echo/ledger/service.py",
    }
    offenders: list[str] = []
    for production_root in production_roots:
        for path in production_root.rglob("*.py"):
            if path == MODULE_PATH:
                continue
            if path.name in ("handoff_vault.py", "turn_runtime.py", "turn_context.py"):
                continue
            rel = str(path.relative_to(ROOT))
            # Task 4 is the first production consumer of the frozen R1
            # ArtifactRef leaf.  The exact symbols/edges and continuing leaf
            # purity are enforced by ledger/test_core_contract.py.
            if rel in task4_projection_consumers:
                continue
            if rel.startswith(("js/connectors/", "js/mobile/", "js/friends/", "js/memory/layers/", "js/appshell/inbox.py", "js/appshell/work_context.py")):
                continue
            if rel == "js/memory/compression.py":
                continue
            offenders.extend(
                str(Path(offender).relative_to(ROOT))
                for offender in mode_contract_reference_offenders_for_source(
                    path,
                    path.read_text(encoding="utf-8"),
                )
            )
    assert offenders == []


def test_change_inventory_gate_is_documented_as_separate_acceptance_condition() -> None:
    assert {
        "js/echo/mode_contract.py",
        "tests/echo/test_r1_client_task_adapter.py",
        "tests/echo/test_r1_mode_contract.py",
        "tests/echo/test_r1_mode_manifest.py",
    } == CHANGE_INVENTORY_ALLOWED_FILES
