from __future__ import annotations

import ast
import dataclasses
import importlib
import inspect
from collections.abc import Mapping
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any, cast

import pytest

from js.echo.turn_context import runtime_partition_key

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "js" / "echo" / "mode_contract.py"


class MyStr(str):
    pass


class CustomMapping(Mapping[str, object]):
    def __iter__(self) -> Any:
        return iter(())

    def __len__(self) -> int:
        return 0

    def __getitem__(self, key: str) -> object:
        raise KeyError(key)


def contract() -> Any:
    return importlib.import_module("js.echo.mode_contract")


def module_tree() -> ast.Module:
    return ast.parse(MODULE_PATH.read_text(encoding="utf-8"))


def assert_exact_error(
    mod: Any,
    exc: BaseException,
    *,
    error_name: str,
    code: str,
    field: str | None,
    detail: str,
    hidden: tuple[str, ...] = (),
) -> None:
    error_type = getattr(mod, error_name)
    assert type(exc) is error_type
    error = cast("Any", exc)
    assert error.code == code
    assert error.field == field
    assert error.detail == detail
    rendered = f"{error} {error.code} {error.field} {error.detail}"
    for value in hidden:
        assert value not in rendered


def work_request_payload(**overrides: object) -> dict[object, object]:
    payload: dict[object, object] = {
        "mode": "work",
        "session": "session-a",
        "workspace": "work-a",
    }
    payload.update(overrides)
    return payload


def make_work_request(mod: Any, **overrides: object) -> Any:
    return mod.ClientTaskRequestV1.from_dict(work_request_payload(**overrides))


def make_work_authority(mod: Any, **overrides: object) -> Any:
    values: dict[str, object] = {
        "mode": mod.AppMode.WORK,
        "mode_runtime_owner": "legacy-work-owner",
        "session": "session-a",
        "workspace": "work-a",
    }
    values.update(overrides)
    return mod.ResolvedTaskAuthorityV1(**values)


def test_batch2_public_contract_symbols_exist_as_distinct_types_and_function() -> None:
    """Removing any Batch2 API must fail at its public leaf boundary."""
    mod = contract()
    assert issubclass(mod.ClientTaskRequestValidationError, mod.ModeContractError)
    assert issubclass(mod.TaskAuthorityError, mod.ModeContractError)
    assert mod.ClientTaskRequestValidationError is not mod.TaskRefValidationError
    assert mod.TaskAuthorityError is not mod.TaskRefValidationError
    assert mod.TaskAuthorityError is not mod.ClientTaskRequestValidationError
    assert dataclasses.is_dataclass(mod.ClientTaskRequestV1)
    assert dataclasses.is_dataclass(mod.ResolvedTaskAuthorityV1)
    assert callable(mod.task_ref_from_client_request_v1)


@pytest.mark.parametrize("root", [[], (), "work", CustomMapping()])
def test_client_request_requires_exact_builtin_dict(root: object) -> None:
    """Accepting mappings or other roots would reopen transport coercion."""
    mod = contract()
    with pytest.raises(Exception) as caught:
        mod.ClientTaskRequestV1.from_dict(root)
    assert_exact_error(
        mod,
        caught.value,
        error_name="ClientTaskRequestValidationError",
        code="invalid_root",
        field=None,
        detail="Client task request payload must be a dict",
    )

    class DictSubclass(dict[object, object]):
        pass

    with pytest.raises(Exception) as subclass_error:
        mod.ClientTaskRequestV1.from_dict(DictSubclass(work_request_payload()))
    assert_exact_error(
        mod,
        subclass_error.value,
        error_name="ClientTaskRequestValidationError",
        code="invalid_root",
        field=None,
        detail="Client task request payload must be a dict",
    )


@pytest.mark.parametrize("key", [1, MyStr("mode")])
def test_client_request_requires_exact_builtin_string_keys(key: object) -> None:
    """Stringifying a decoded key would bypass the exact JSON envelope."""
    mod = contract()
    payload = work_request_payload()
    payload.pop("mode")
    payload[key] = "work"
    with pytest.raises(Exception) as caught:
        mod.ClientTaskRequestV1.from_dict(payload)
    assert_exact_error(
        mod,
        caught.value,
        error_name="ClientTaskRequestValidationError",
        code="invalid_key",
        field=None,
        detail="Client task request field names must be strings",
    )


@pytest.mark.parametrize(
    "forbidden",
    [
        "owner",
        "run",
        "product",
        "product_id",
        "account_id",
        "principal",
        "key_hash",
        "role",
        "canonical_hash",
        "task_ref_hash",
        "partition_key",
    ],
)
def test_client_request_rejects_authority_fields_without_echo(forbidden: str) -> None:
    """A client field must never enter trusted authority or an error log."""
    mod = contract()
    payload = work_request_payload()
    payload[forbidden] = "sentinel-secret-value"
    with pytest.raises(Exception) as caught:
        mod.ClientTaskRequestV1.from_dict(payload)
    assert_exact_error(
        mod,
        caught.value,
        error_name="ClientTaskRequestValidationError",
        code="unknown_field",
        field=None,
        detail="Client task request contains unknown fields",
        hidden=(forbidden, "sentinel-secret-value"),
    )


def test_client_request_validation_order_is_key_unknown_missing_then_mode() -> None:
    """Changing validation order could expose an untrusted field or value."""
    mod = contract()

    with pytest.raises(Exception) as unknown:
        mod.ClientTaskRequestV1.from_dict({"secret-key": "sentinel", "mode": "bad"})
    assert_exact_error(
        mod,
        unknown.value,
        error_name="ClientTaskRequestValidationError",
        code="unknown_field",
        field=None,
        detail="Client task request contains unknown fields",
        hidden=("secret-key", "sentinel"),
    )

    with pytest.raises(Exception) as missing:
        mod.ClientTaskRequestV1.from_dict({"session": True, "workspace": "bad:path"})
    assert_exact_error(
        mod,
        missing.value,
        error_name="ClientTaskRequestValidationError",
        code="missing_field",
        field="mode",
        detail="missing client task request field",
    )

    with pytest.raises(Exception) as bad_mode:
        mod.ClientTaskRequestV1.from_dict({"mode": "bad", "session": True, "workspace": "bad:path"})
    assert_exact_error(
        mod,
        bad_mode.value,
        error_name="ClientTaskRequestValidationError",
        code="invalid_value",
        field="mode",
        detail="mode must be personal or work",
    )


def test_client_request_direct_constructor_requires_exact_app_mode() -> None:
    """A direct internal request must not silently coerce strings or enums."""
    mod = contract()
    valid = mod.ClientTaskRequestV1(mode=mod.AppMode.PERSONAL)
    assert valid.mode is mod.AppMode.PERSONAL
    for value in ("personal", MyStr("personal"), True, 1, None):
        with pytest.raises(Exception) as caught:
            mod.ClientTaskRequestV1(mode=value)
        assert_exact_error(
            mod,
            caught.value,
            error_name="ClientTaskRequestValidationError",
            code="invalid_type",
            field="mode",
            detail="client task request mode must be AppMode",
        )


@pytest.mark.parametrize("value", [None, "s", "session/a:b-1_2.3", "a" * 192])
def test_client_request_session_accepts_only_v1_identity_or_null(value: str | None) -> None:
    """Valid optional sessions must survive parsing without rewriting."""
    mod = contract()
    payload = work_request_payload(session=value)
    assert mod.ClientTaskRequestV1.from_dict(payload).session == value


@pytest.mark.parametrize(
    ("value", "code", "detail"),
    [
        (True, "invalid_type", "session must be text"),
        (1, "invalid_type", "session must be text"),
        (MyStr("session-a"), "invalid_type", "session must be text"),
        ("", "invalid_value", "session has an invalid format"),
        (" session", "invalid_value", "session has an invalid format"),
        ("session ", "invalid_value", "session has an invalid format"),
        ("a" * 193, "invalid_value", "session has an invalid format"),
        (r"session\bad", "invalid_value", "session has an invalid format"),
        ("session<bad", "invalid_value", "session has an invalid format"),
        ("session\x00bad", "invalid_value", "session has an invalid format"),
        ("e\u0301", "noncanonical_unicode", "session must be NFC-normalized"),
    ],
)
def test_client_request_session_errors_are_exact_subtype(value: object, code: str, detail: str) -> None:
    """Session coercion or subtype leakage would blur the transport boundary."""
    mod = contract()
    with pytest.raises(Exception) as caught:
        mod.ClientTaskRequestV1.from_dict(work_request_payload(session=value))
    assert_exact_error(
        mod,
        caught.value,
        error_name="ClientTaskRequestValidationError",
        code=code,
        field="session",
        detail=detail,
    )


def test_client_request_personal_and_work_workspace_invariants() -> None:
    """Personal must remain pathless and Work must name an opaque handle."""
    mod = contract()
    for payload in ({"mode": "personal"}, {"mode": "personal", "workspace": None}):
        request = mod.ClientTaskRequestV1.from_dict(payload)
        assert request.mode is mod.AppMode.PERSONAL
        assert request.workspace is None

    with pytest.raises(Exception) as personal_workspace:
        mod.ClientTaskRequestV1.from_dict({"mode": "personal", "workspace": "work-a"})
    assert_exact_error(
        mod,
        personal_workspace.value,
        error_name="ClientTaskRequestValidationError",
        code="workspace_mode_mismatch",
        field="workspace",
        detail="personal workspace must be null",
    )

    for handle in ("w", "work-default", "team.alpha_01", "a" * 128):
        assert mod.ClientTaskRequestV1.from_dict({"mode": "work", "workspace": handle}).workspace == handle

    for payload in ({"mode": "work"}, {"mode": "work", "workspace": None}, {"mode": "work", "workspace": ""}):
        with pytest.raises(Exception) as missing:
            mod.ClientTaskRequestV1.from_dict(payload)
        assert_exact_error(
            mod,
            missing.value,
            error_name="ClientTaskRequestValidationError",
            code="workspace_mode_mismatch",
            field="workspace",
            detail="work workspace must be non-empty",
        )


@pytest.mark.parametrize(
    "workspace",
    [
        True,
        1,
        MyStr("work-a"),
        "team:alpha",
        "/tmp/work",
        "../work",
        "./work",
        "a/b",
        r"C:\work",
        "file://work",
        "https://work",
        ".",
        "..",
        ".hidden",
        " work",
        "work ",
        "a" * 129,
    ],
)
def test_client_request_work_workspace_rejects_types_paths_and_dot_shapes(workspace: object) -> None:
    """A workspace handle must never be interpreted as a filesystem path or URI."""
    mod = contract()
    with pytest.raises(Exception) as caught:
        mod.ClientTaskRequestV1.from_dict({"mode": "work", "workspace": workspace})
    code = "invalid_type" if type(workspace) is not str else "invalid_value"
    detail = "workspace must be text" if code == "invalid_type" else "workspace must be an opaque handle"
    assert_exact_error(
        mod,
        caught.value,
        error_name="ClientTaskRequestValidationError",
        code=code,
        field="workspace",
        detail=detail,
    )


def test_client_request_serialization_is_minimal_canonical_and_authority_free() -> None:
    """Serialization must not grow an owner, run, product, or identity field."""
    mod = contract()
    request = make_work_request(mod)
    assert request.to_dict() == {
        "mode": "work",
        "session": "session-a",
        "workspace": "work-a",
    }
    assert request.canonical_bytes() == b'{"mode":"work","session":"session-a","workspace":"work-a"}'
    assert set(request.to_dict()) == {"mode", "session", "workspace"}


def test_client_request_is_frozen_slotted_and_input_mutation_safe() -> None:
    """Parsed intent must not retain or expose a mutable decoded payload."""
    mod = contract()
    payload = work_request_payload()
    request = mod.ClientTaskRequestV1.from_dict(payload)
    payload["mode"] = "personal"
    payload["session"] = "changed"
    payload["workspace"] = None
    assert request.to_dict() == {"mode": "work", "session": "session-a", "workspace": "work-a"}
    assert not hasattr(request, "__dict__")
    with pytest.raises(FrozenInstanceError):
        request.session = "changed"


def test_resolved_authority_has_only_physical_runtime_identity_fields() -> None:
    """Adding account/principal fields would invite owner substitution."""
    mod = contract()
    assert tuple(field.name for field in dataclasses.fields(mod.ResolvedTaskAuthorityV1)) == (
        "mode",
        "mode_runtime_owner",
        "session",
        "workspace",
    )
    authority = make_work_authority(mod)
    assert not hasattr(authority, "__dict__")
    with pytest.raises(FrozenInstanceError):
        authority.session = "changed"


def test_resolved_authority_requires_exact_app_mode() -> None:
    """Trusted authority cannot accept a client-like mode string."""
    mod = contract()
    for value in ("work", MyStr("work"), True, 1, None):
        with pytest.raises(Exception) as caught:
            make_work_authority(mod, mode=value)
        assert_exact_error(
            mod,
            caught.value,
            error_name="TaskAuthorityError",
            code="invalid_type",
            field="mode",
            detail="resolved authority mode must be AppMode",
        )


@pytest.mark.parametrize(
    ("field", "value", "code", "detail"),
    [
        ("mode_runtime_owner", True, "invalid_type", "owner must be text"),
        ("mode_runtime_owner", "owner/a", "invalid_value", "owner has an invalid format"),
        ("mode_runtime_owner", "a" * 193, "invalid_value", "owner has an invalid format"),
        ("session", True, "invalid_type", "session must be text"),
        ("session", "session<bad", "invalid_value", "session has an invalid format"),
        ("session", "a" * 193, "invalid_value", "session has an invalid format"),
        ("workspace", True, "invalid_type", "workspace must be text"),
        ("workspace", "bad:path", "invalid_value", "workspace must be an opaque handle"),
        ("workspace", None, "workspace_mode_mismatch", "work workspace must be non-empty"),
    ],
)
def test_resolved_authority_rewraps_scalar_failures(
    field: str,
    value: object,
    code: str,
    detail: str,
) -> None:
    """Authority construction must not leak TaskRef validation subtypes."""
    mod = contract()
    with pytest.raises(Exception) as caught:
        make_work_authority(mod, **{field: value})
    expected_field = "owner" if field == "mode_runtime_owner" else field
    assert_exact_error(
        mod,
        caught.value,
        error_name="TaskAuthorityError",
        code=code,
        field=expected_field,
        detail=detail,
    )


def test_resolved_authority_personal_and_work_workspace_invariants() -> None:
    """Server authority must enforce the same mode/workspace partition boundary."""
    mod = contract()
    personal = mod.ResolvedTaskAuthorityV1(
        mode=mod.AppMode.PERSONAL,
        mode_runtime_owner="legacy-personal-owner",
        session="session-p",
        workspace=None,
    )
    assert personal.workspace is None
    with pytest.raises(Exception) as caught:
        mod.ResolvedTaskAuthorityV1(
            mode=mod.AppMode.PERSONAL,
            mode_runtime_owner="legacy-personal-owner",
            session="session-p",
            workspace="work-a",
        )
    assert_exact_error(
        mod,
        caught.value,
        error_name="TaskAuthorityError",
        code="workspace_mode_mismatch",
        field="workspace",
        detail="personal workspace must be null",
    )


def test_adapter_builds_work_task_ref_only_from_server_authority_and_run() -> None:
    """Owner and run must have exactly one trusted dataflow into TaskRef."""
    mod = contract()
    request = make_work_request(mod)
    authority = make_work_authority(mod)
    ref = mod.task_ref_from_client_request_v1(
        request,
        authority=authority,
        server_run_id="server-run-a",
    )
    assert ref == mod.TaskRef(
        mode=mod.AppMode.WORK,
        owner="legacy-work-owner",
        session="session-a",
        run="server-run-a",
        workspace="work-a",
    )
    assert ref.legacy_product_id == "js-work"


def test_adapter_builds_personal_task_ref_without_workspace() -> None:
    """The Personal adapter result must remain workspace-free."""
    mod = contract()
    request = mod.ClientTaskRequestV1.from_dict({"mode": "personal"})
    authority = mod.ResolvedTaskAuthorityV1(
        mode=mod.AppMode.PERSONAL,
        mode_runtime_owner="legacy-personal-owner",
        session="session-p",
        workspace=None,
    )
    ref = mod.task_ref_from_client_request_v1(
        request,
        authority=authority,
        server_run_id="server-run-p",
    )
    assert ref.mode is mod.AppMode.PERSONAL
    assert ref.owner == "legacy-personal-owner"
    assert ref.session == "session-p"
    assert ref.run == "server-run-p"
    assert ref.workspace is None
    assert ref.legacy_product_id == "js-agent"


def test_adapter_uses_authority_session_when_client_omits_session() -> None:
    """An omitted client session must not erase the server-resolved session."""
    mod = contract()
    request = mod.ClientTaskRequestV1.from_dict({"mode": "work", "workspace": "work-a"})
    ref = mod.task_ref_from_client_request_v1(
        request,
        authority=make_work_authority(mod),
        server_run_id="server-run-a",
    )
    assert request.session is None
    assert ref.session == "session-a"


@pytest.mark.parametrize(
    ("request_payload", "authority", "code", "field", "detail", "hidden"),
    [
        (
            {"mode": "personal"},
            {"mode": "work", "workspace": "work-a"},
            "mode_authority_conflict",
            "mode",
            "requested mode does not match resolved authority",
            (),
        ),
        (
            {"mode": "work", "session": "client-secret-session", "workspace": "work-a"},
            {"session": "server-secret-session"},
            "session_authority_conflict",
            "session",
            "requested session does not match resolved authority",
            ("client-secret-session", "server-secret-session"),
        ),
        (
            {"mode": "work", "session": "session-a", "workspace": "client-secret-work"},
            {"workspace": "server-secret-work"},
            "workspace_authority_conflict",
            "workspace",
            "requested workspace does not match resolved authority",
            ("client-secret-work", "server-secret-work"),
        ),
    ],
)
def test_adapter_rejects_client_authority_conflicts_without_echo(
    request_payload: dict[str, object],
    authority: dict[str, object],
    code: str,
    field: str,
    detail: str,
    hidden: tuple[str, ...],
) -> None:
    """Conflicting client intent must fail closed instead of being corrected."""
    mod = contract()
    parsed = mod.ClientTaskRequestV1.from_dict(request_payload)
    resolved_values: dict[str, object] = {
        "mode": mod.AppMode.WORK,
        "mode_runtime_owner": "legacy-work-owner",
        "session": "session-a",
        "workspace": "work-a",
    }
    if authority.get("mode") == "work":
        resolved_values["mode"] = mod.AppMode.WORK
    resolved_values.update({key: value for key, value in authority.items() if key != "mode"})
    resolved = mod.ResolvedTaskAuthorityV1(**resolved_values)
    with pytest.raises(Exception) as caught:
        mod.task_ref_from_client_request_v1(parsed, authority=resolved, server_run_id="server-run")
    assert_exact_error(
        mod,
        caught.value,
        error_name="TaskAuthorityError",
        code=code,
        field=field,
        detail=detail,
        hidden=hidden,
    )


def test_adapter_rejects_raw_and_subclass_request_or_authority() -> None:
    """Only exact parsed request and exact resolved authority types may adapt."""
    mod = contract()
    request = make_work_request(mod)
    authority = make_work_authority(mod)

    class RequestSubclass(mod.ClientTaskRequestV1):
        pass

    class AuthoritySubclass(mod.ResolvedTaskAuthorityV1):
        pass

    bad_requests = [work_request_payload(), RequestSubclass(mode=mod.AppMode.WORK, session="session-a", workspace="work-a")]
    for bad_request in bad_requests:
        with pytest.raises(Exception) as caught:
            mod.task_ref_from_client_request_v1(
                bad_request,
                authority=authority,
                server_run_id="server-run-a",
            )
        assert_exact_error(
            mod,
            caught.value,
            error_name="TaskAuthorityError",
            code="invalid_request_authority",
            field=None,
            detail="client task request must be parsed before adaptation",
        )

    bad_authorities = [
        {
            "mode": mod.AppMode.WORK,
            "mode_runtime_owner": "legacy-work-owner",
            "session": "session-a",
            "workspace": "work-a",
        },
        AuthoritySubclass(
            mode=mod.AppMode.WORK,
            mode_runtime_owner="legacy-work-owner",
            session="session-a",
            workspace="work-a",
        ),
    ]
    for bad_authority in bad_authorities:
        with pytest.raises(Exception) as caught:
            mod.task_ref_from_client_request_v1(
                request,
                authority=bad_authority,
                server_run_id="server-run-a",
            )
        assert_exact_error(
            mod,
            caught.value,
            error_name="TaskAuthorityError",
            code="invalid_request_authority",
            field=None,
            detail="resolved task authority is required",
        )


@pytest.mark.parametrize(
    ("server_run_id", "code", "detail"),
    [
        (True, "invalid_type", "run must be text"),
        (MyStr("server-run"), "invalid_type", "run must be text"),
        ("", "invalid_value", "run has an invalid format"),
        ("bad<run", "invalid_value", "run has an invalid format"),
        ("a" * 193, "invalid_value", "run has an invalid format"),
    ],
)
def test_adapter_rewraps_server_run_failures(server_run_id: object, code: str, detail: str) -> None:
    """Invalid run provenance input must surface only as TaskAuthorityError."""
    mod = contract()
    with pytest.raises(Exception) as caught:
        mod.task_ref_from_client_request_v1(
            make_work_request(mod),
            authority=make_work_authority(mod),
            server_run_id=server_run_id,
        )
    assert_exact_error(
        mod,
        caught.value,
        error_name="TaskAuthorityError",
        code=code,
        field="run",
        detail=detail,
    )


def test_client_json_run_is_unknown_and_leaf_adapter_does_not_claim_run_provenance() -> None:
    """Batch2 proves no client-to-run flow; a future bridge must prove factory provenance."""
    mod = contract()
    with pytest.raises(Exception) as caught:
        mod.ClientTaskRequestV1.from_dict(
            {"mode": "work", "workspace": "work-a", "run": "client-secret-run"}
        )
    assert_exact_error(
        mod,
        caught.value,
        error_name="ClientTaskRequestValidationError",
        code="unknown_field",
        field=None,
        detail="Client task request contains unknown fields",
        hidden=("run", "client-secret-run"),
    )


def test_adapter_signature_and_task_ref_dataflow_are_narrow() -> None:
    """Adding an account, product, owner, or raw run source must fail this guard."""
    mod = contract()
    signature = inspect.signature(mod.task_ref_from_client_request_v1)
    assert tuple(signature.parameters) == ("request", "authority", "server_run_id")
    assert signature.parameters["request"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert signature.parameters["authority"].kind is inspect.Parameter.KEYWORD_ONLY
    assert signature.parameters["server_run_id"].kind is inspect.Parameter.KEYWORD_ONLY

    tree = module_tree()
    fn = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "task_ref_from_client_request_v1"
    )
    body_source = ast.unparse(fn)
    for forbidden in ("account_id", "principal", "key_hash", "product_id", "settings", "auth.get", "uuid"):
        assert forbidden not in body_source

    task_ref_calls = [
        node
        for node in ast.walk(fn)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "TaskRef"
    ]
    assert len(task_ref_calls) == 1
    keywords = {keyword.arg: ast.unparse(keyword.value) for keyword in task_ref_calls[0].keywords}
    assert keywords == {
        "mode": "authority.mode",
        "owner": "authority.mode_runtime_owner",
        "session": "authority.session",
        "run": "server_run_id",
        "workspace": "authority.workspace",
    }


def test_client_from_dict_never_builds_internal_task_ref() -> None:
    """The client DTO parser must not delegate to the internal TaskRef parser."""
    tree = module_tree()
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "ClientTaskRequestV1")
    from_dict = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "from_dict")
    assert "TaskRef.from_dict" not in ast.unparse(from_dict)


def test_batch2_contract_remains_a_leaf_without_production_callsites() -> None:
    """Wiring transport/runtime in this batch would change live authority behavior."""
    target = "js.echo.mode_contract"
    offenders: list[str] = []
    for production_root in (ROOT / "js", ROOT / "js_work"):
        for path in production_root.rglob("*.py"):
            if path == MODULE_PATH:
                continue
            if path.name in ("handoff_vault.py", "turn_runtime.py", "turn_context.py"):
                continue
            if str(path.relative_to(ROOT)).startswith("js/connectors/"):
                continue
            if str(path.relative_to(ROOT)).startswith("js/mobile/"):
                continue
            if str(path.relative_to(ROOT)).startswith("js/friends/"):
                continue
            if str(path.relative_to(ROOT)).startswith("js/memory/layers/"):
                continue
            if str(path.relative_to(ROOT)).startswith("js/memory/compression.py"):
                continue
            if str(path.relative_to(ROOT)).startswith("js/appshell/inbox.py"):
                continue
            if str(path.relative_to(ROOT)).startswith("js/appshell/work_context.py"):
                continue
            if str(path.relative_to(ROOT)).startswith("js/agent/tool_executor.py"):
                continue
            if str(path.relative_to(ROOT)).startswith("js/appshell/routers.py"):
                continue
            if str(path.relative_to(ROOT)).startswith("js/echo/ledger/"):
                continue
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import) and any(alias.name == target for alias in node.names):
                    offenders.append(str(path.relative_to(ROOT)))
                    break
                if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == target:
                    offenders.append(str(path.relative_to(ROOT)))
                    break
    assert offenders == []


def test_legacy_runtime_partition_key_golden_fixtures_are_unchanged() -> None:
    """A contract-only batch must not migrate legacy product/owner/session partitions."""
    assert runtime_partition_key("js-agent", "owner-a", "session-a") == (
        "echo-session:ce50e377c15ca979aeccc164f3d104985ab689b201c9f9b54e0523ca0d02769e"
    )
    assert runtime_partition_key("js-work", "owner-a", "session-a") == (
        "echo-session:9a3df0280436973dbd7c2968d9477ce6fa0393ab166521e9fce664abd6097360"
    )
