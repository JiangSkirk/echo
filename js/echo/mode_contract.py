from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, cast, overload

from js.echo.primitives import canonical_json_bytes

# ruff: noqa: TC006

LEGACY_PERSONAL_PRODUCT_ID: Final = "js-agent"
LEGACY_WORK_PRODUCT_ID: Final = "js-work"
TASK_REF_SCHEMA_VERSION: Final = 1
TASK_REF_HASH_DOMAIN: Final = b"js-agent:task-ref:v1\0"
MODE_MANIFEST_SCHEMA_VERSION: Final = 1
MODE_MANIFEST_HASH_DOMAIN: Final = b"js-agent:mode-manifest:v1\0"
DIRECTORY_GRANT_SCHEMA_VERSION: Final = 1
DIRECTORY_GRANT_HASH_DOMAIN: Final = b"js-agent:directory-grant:v1\0"
ATTENTION_ITEM_SCHEMA_VERSION: Final = 1
ATTENTION_ITEM_HASH_DOMAIN: Final = b"js-agent:attention-item:v1\0"
ARTIFACT_REF_SCHEMA_VERSION: Final = 1
ARTIFACT_REF_HASH_DOMAIN: Final = b"js-agent:artifact-ref:v1\0"
CONNECTOR_MANIFEST_SCHEMA_VERSION: Final = 1
CONNECTOR_MANIFEST_HASH_DOMAIN: Final = b"js-agent:connector-manifest:v1\0"
CONNECTION_REF_SCHEMA_VERSION: Final = 1
CONNECTION_REF_HASH_DOMAIN: Final = b"js-agent:connection-ref:v1\0"

_OWNER_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}$")
_SESSION_RUN_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")
_WORKSPACE_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_TASK_REF_FIELDS: Final = frozenset({"schema_version", "mode", "owner", "session", "run", "workspace"})
_TASK_REF_ORDER: Final = ("schema_version", "mode", "owner", "session", "run", "workspace")
_CLIENT_TASK_REQUEST_FIELDS: Final = frozenset({"mode", "session", "workspace"})


class AppMode(StrEnum):
    PERSONAL = "personal"
    WORK = "work"


class ModeContractError(ValueError):
    __slots__ = ("_code", "_field", "_detail")

    def __init__(self, *, code: str, field: str | None, detail: str) -> None:
        self._code = code
        self._field = field
        self._detail = detail
        super().__init__(f"{code}: {field or '-'}: {detail}")

    @property
    def code(self) -> str:
        return self._code

    @property
    def field(self) -> str | None:
        return self._field

    @property
    def detail(self) -> str:
        return self._detail


class ModeMappingError(ModeContractError):
    pass


class TaskRefValidationError(ModeContractError):
    pass


class UnknownFieldError(TaskRefValidationError):
    pass


class ClientTaskRequestValidationError(ModeContractError):
    pass


class TaskAuthorityError(ModeContractError):
    pass


class ModeManifestValidationError(ModeContractError):
    pass


class DirectoryGrantValidationError(ModeContractError):
    pass


class AttentionItemValidationError(ModeContractError):
    pass


class ArtifactRefValidationError(ModeContractError):
    pass


class ConnectorManifestValidationError(ModeContractError):
    pass


class ConnectionRefValidationError(ModeContractError):
    pass


_DIRECTORY_GRANT_FIELDS: Final = frozenset({"schema_version", "mode", "workspace", "root"})
_DIRECTORY_GRANT_FIELD_ORDER: Final = ("schema_version", "mode", "workspace", "root")
_DIRECTORY_GRANT_ROOT_RE: Final = re.compile(r"^/(?:[^/\s\\]+(?:/[^/\s\\]+)*)?$")


def _grant_error(*, code: str, field: str | None, detail: str) -> DirectoryGrantValidationError:
    return DirectoryGrantValidationError(code=code, field=field, detail=detail)


def _grant_root(value: object) -> str:
    if type(value) is not str:
        raise _grant_error(code="invalid_type", field="root", detail="root must be a string")
    if not value.startswith("/"):
        raise _grant_error(code="invalid_value", field="root", detail="root must be absolute")
    if unicodedata.normalize("NFC", value) != value:
        raise _grant_error(code="noncanonical_unicode", field="root", detail="root must be NFC-normalized")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise _grant_error(code="invalid_value", field="root", detail="root has control characters")
    if len(value) > 4096:
        raise _grant_error(code="invalid_value", field="root", detail="root exceeds limit")
    if _DIRECTORY_GRANT_ROOT_RE.fullmatch(value) is None:
        raise _grant_error(code="invalid_value", field="root", detail="root is invalid")
    parts = value.split("/")
    if ".." in parts or "." in parts:
        raise _grant_error(code="invalid_value", field="root", detail="root must not contain . or .. segments")
    if "//" in value:
        raise _grant_error(code="invalid_value", field="root", detail="root must not contain double slashes")
    if value != "/" and value.endswith("/"):
        raise _grant_error(code="invalid_value", field="root", detail="root must not have trailing slash")
    return value


def _grant_dict(payload: object) -> dict[str, object]:
    if type(payload) is not dict:
        raise _grant_error(code="invalid_root", field=None, detail="grant payload must be a dict")
    if any(type(key) is not str for key in payload):
        raise _grant_error(code="invalid_key", field=None, detail="grant keys must be strings")
    if set(payload) - _DIRECTORY_GRANT_FIELDS:
        raise _grant_error(code="unknown_field", field=None, detail="grant contains unknown fields")
    for field in _DIRECTORY_GRANT_FIELD_ORDER:
        if field not in payload:
            raise _grant_error(code="missing_field", field=field, detail="grant field is required")
    return cast("dict[str, object]", payload)


_MODE_MANIFEST_FIELDS: Final = frozenset(
    {
        "schema_version",
        "mode",
        "feature_ids",
        "tool_ids",
        "connector_ids",
        "workspace_required",
    }
)
_MODE_MANIFEST_FIELD_ORDER: Final = (
    "schema_version",
    "mode",
    "feature_ids",
    "tool_ids",
    "connector_ids",
    "workspace_required",
)
_MODE_MANIFEST_ID_RE: Final = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")


def _manifest_error(*, code: str, field: str | None, detail: str) -> ModeManifestValidationError:
    return ModeManifestValidationError(code=code, field=field, detail=detail)


def _manifest_ids(value: object, *, field: str, decoded: bool) -> tuple[str, ...]:
    expected = list if decoded else tuple
    if type(value) is not expected:
        raise _manifest_error(code="invalid_type", field=field, detail="capability IDs have an invalid type")
    raw_ids = cast("list[object] | tuple[object, ...]", value)
    result: list[str] = []
    for item in raw_ids:
        if type(item) is not str:
            raise _manifest_error(code="invalid_type", field=field, detail="capability IDs have an invalid type")
        if unicodedata.normalize("NFC", item) != item:
            raise _manifest_error(code="noncanonical_unicode", field=field, detail="capability IDs must be NFC")
        if (
            not item
            or len(item) > 128
            or item != item.strip()
            or any(unicodedata.category(char).startswith("C") for char in item)
            or _MODE_MANIFEST_ID_RE.fullmatch(item) is None
        ):
            raise _manifest_error(code="invalid_value", field=field, detail="capability ID is invalid")
        result.append(item)
    ids = tuple(result)
    if len(set(ids)) != len(ids):
        raise _manifest_error(code="duplicate_id", field=field, detail="capability IDs must be unique")
    if ids != tuple(sorted(ids)):
        raise _manifest_error(
            code="noncanonical_order", field=field, detail="capability IDs must be sorted"
        )
    return ids


def _manifest_dict(payload: object) -> dict[str, object]:
    if type(payload) is not dict:
        raise _manifest_error(code="invalid_root", field=None, detail="manifest payload must be a dict")
    if any(type(key) is not str for key in payload):
        raise _manifest_error(code="invalid_key", field=None, detail="manifest keys must be strings")
    if set(payload) - _MODE_MANIFEST_FIELDS:
        raise _manifest_error(code="unknown_field", field=None, detail="manifest contains unknown fields")
    for field in _MODE_MANIFEST_FIELD_ORDER:
        if field not in payload:
            raise _manifest_error(code="missing_field", field=field, detail="manifest field is required")
    return cast("dict[str, object]", payload)


def _manifest_schema(value: object) -> None:
    if type(value) is not int:
        raise _manifest_error(code="invalid_type", field="schema_version", detail="schema_version must be 1")
    if value != MODE_MANIFEST_SCHEMA_VERSION:
        raise _manifest_error(code="invalid_value", field="schema_version", detail="schema_version must be 1")


def app_mode_from_json(value: object) -> AppMode:
    if type(value) is not str:
        raise ModeMappingError(code="invalid_value", field="mode", detail="mode must be personal or work")
    if value == "personal":
        return AppMode.PERSONAL
    if value == "work":
        return AppMode.WORK
    raise ModeMappingError(code="invalid_value", field="mode", detail="mode must be personal or work")


def _coerce_app_mode(value: object) -> AppMode:
    if type(value) is AppMode:
        return value
    return app_mode_from_json(value)


def product_id_from_mode(mode: AppMode | str) -> str:
    parsed = _coerce_app_mode(mode)
    if parsed is AppMode.PERSONAL:
        return LEGACY_PERSONAL_PRODUCT_ID
    return LEGACY_WORK_PRODUCT_ID


def mode_from_product_id(product_id: object) -> AppMode:
    if type(product_id) is not str:
        raise ModeMappingError(code="invalid_value", field="product_id", detail="unknown legacy product_id")
    if product_id == LEGACY_PERSONAL_PRODUCT_ID:
        return AppMode.PERSONAL
    if product_id == LEGACY_WORK_PRODUCT_ID:
        return AppMode.WORK
    raise ModeMappingError(code="invalid_value", field="product_id", detail="unknown legacy product_id")


def assert_mode_product_compatible(*, mode: AppMode | str, product_id: object) -> None:
    expected = product_id_from_mode(mode)
    if type(product_id) is not str:
        raise ModeMappingError(code="invalid_type", field="product_id", detail="product_id must be text")
    if product_id not in (LEGACY_PERSONAL_PRODUCT_ID, LEGACY_WORK_PRODUCT_ID):
        raise ModeMappingError(code="invalid_value", field="product_id", detail="unknown legacy product_id")
    if product_id != expected:
        raise ModeMappingError(
            code="mode_product_conflict",
            field="product_id",
            detail="product_id must be derived from mode",
        )


def _require_exact_dict(payload: object) -> dict[str, object]:
    if type(payload) is not dict:
        raise TaskRefValidationError(code="invalid_root", field=None, detail="TaskRef payload must be a dict")
    if any(type(key) is not str for key in payload):
        raise TaskRefValidationError(code="invalid_key", field=None, detail="TaskRef field names must be strings")
    if set(payload) - _TASK_REF_FIELDS:
        raise UnknownFieldError(
            code="unknown_field",
            field=None,
            detail="TaskRef payload contains unknown fields",
        )
    for field in _TASK_REF_ORDER:
        if field not in payload:
            raise TaskRefValidationError(code="missing_field", field=field, detail="missing TaskRef field")
    return payload


def _validate_schema_version(value: object) -> None:
    if type(value) is not int or value != TASK_REF_SCHEMA_VERSION:
        raise TaskRefValidationError(
            code="invalid_type",
            field="schema_version",
            detail="schema_version must be 1",
        )


def _require_exact_text(value: object, *, field: str) -> str:
    if type(value) is not str:
        raise TaskRefValidationError(code="invalid_type", field=field, detail=f"{field} must be text")
    if unicodedata.normalize("NFC", value) != value:
        raise TaskRefValidationError(
            code="noncanonical_unicode",
            field=field,
            detail=f"{field} must be NFC-normalized",
        )
    if value != value.strip():
        raise TaskRefValidationError(code="invalid_value", field=field, detail=f"{field} has an invalid format")
    if any(unicodedata.category(ch).startswith("C") for ch in value):
        raise TaskRefValidationError(code="invalid_value", field=field, detail=f"{field} has an invalid format")
    return value


def _validate_identity(value: object, *, field: str, pattern: re.Pattern[str], max_chars: int) -> str:
    text = _require_exact_text(value, field=field)
    if not text:
        raise TaskRefValidationError(code="invalid_value", field=field, detail=f"{field} has an invalid format")
    if len(text) > max_chars or pattern.fullmatch(text) is None:
        raise TaskRefValidationError(code="invalid_value", field=field, detail=f"{field} has an invalid format")
    return text


def _validate_workspace(value: object, *, mode: AppMode) -> str | None:
    if mode is AppMode.PERSONAL:
        if value is not None:
            raise TaskRefValidationError(
                code="workspace_mode_mismatch",
                field="workspace",
                detail="personal workspace must be null",
            )
        return None
    if value is None:
        raise TaskRefValidationError(
            code="workspace_mode_mismatch",
            field="workspace",
            detail="work workspace must be non-empty",
        )
    if type(value) is not str:
        raise TaskRefValidationError(code="invalid_type", field="workspace", detail="workspace must be text")
    text = value
    if unicodedata.normalize("NFC", text) != text:
        raise TaskRefValidationError(
            code="noncanonical_unicode",
            field="workspace",
            detail="workspace must be NFC-normalized",
        )
    if not text:
        raise TaskRefValidationError(
            code="workspace_mode_mismatch",
            field="workspace",
            detail="work workspace must be non-empty",
        )
    if (
        text != text.strip()
        or any(unicodedata.category(ch).startswith("C") for ch in text)
        or len(text) > 128
        or _WORKSPACE_RE.fullmatch(text) is None
    ):
        raise TaskRefValidationError(
            code="invalid_value",
            field="workspace",
            detail="workspace must be an opaque handle",
        )
    return text


@dataclass(frozen=True, slots=True)
class ClientTaskRequestV1:
    mode: AppMode
    session: str | None = None
    workspace: str | None = None

    def __post_init__(self) -> None:
        if type(self.mode) is not AppMode:
            raise ClientTaskRequestValidationError(
                code="invalid_type",
                field="mode",
                detail="client task request mode must be AppMode",
            )
        try:
            session = self.session
            if session is not None:
                session = _validate_identity(
                    cast(object, session),
                    field="session",
                    pattern=_SESSION_RUN_RE,
                    max_chars=192,
                )
            workspace = _validate_workspace(cast(object, self.workspace), mode=self.mode)
        except ModeContractError as exc:
            raise ClientTaskRequestValidationError(
                code=exc.code,
                field=exc.field,
                detail=exc.detail,
            ) from None
        object.__setattr__(self, "session", session)
        object.__setattr__(self, "workspace", workspace)

    @classmethod
    def from_dict(cls, payload: object) -> ClientTaskRequestV1:
        if type(payload) is not dict:
            raise ClientTaskRequestValidationError(
                code="invalid_root",
                field=None,
                detail="Client task request payload must be a dict",
            )
        if any(type(key) is not str for key in payload):
            raise ClientTaskRequestValidationError(
                code="invalid_key",
                field=None,
                detail="Client task request field names must be strings",
            )
        if set(payload) - _CLIENT_TASK_REQUEST_FIELDS:
            raise ClientTaskRequestValidationError(
                code="unknown_field",
                field=None,
                detail="Client task request contains unknown fields",
            )
        if "mode" not in payload:
            raise ClientTaskRequestValidationError(
                code="missing_field",
                field="mode",
                detail="missing client task request field",
            )
        try:
            mode = app_mode_from_json(payload["mode"])
        except ModeContractError as exc:
            raise ClientTaskRequestValidationError(
                code=exc.code,
                field=exc.field,
                detail=exc.detail,
            ) from None
        return ClientTaskRequestV1(
            mode=mode,
            # Avoid a receiver method call so the leaf-module call-shape gate stays closed.
            session=cast(str | None, payload["session"] if "session" in payload else None),  # noqa: SIM401
            workspace=cast(
                str | None,
                payload["workspace"] if "workspace" in payload else None,  # noqa: SIM401
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "mode": self.mode.value,
            "session": self.session,
            "workspace": self.workspace,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())


@dataclass(frozen=True, slots=True)
class ResolvedTaskAuthorityV1:
    mode: AppMode
    mode_runtime_owner: str
    session: str
    workspace: str | None

    def __post_init__(self) -> None:
        if type(self.mode) is not AppMode:
            raise TaskAuthorityError(
                code="invalid_type",
                field="mode",
                detail="resolved authority mode must be AppMode",
            )
        try:
            owner = _validate_identity(
                cast(object, self.mode_runtime_owner),
                field="owner",
                pattern=_OWNER_RE,
                max_chars=192,
            )
            session = _validate_identity(
                cast(object, self.session),
                field="session",
                pattern=_SESSION_RUN_RE,
                max_chars=192,
            )
            workspace = _validate_workspace(cast(object, self.workspace), mode=self.mode)
        except ModeContractError as exc:
            raise TaskAuthorityError(
                code=exc.code,
                field=exc.field,
                detail=exc.detail,
            ) from None
        object.__setattr__(self, "mode_runtime_owner", owner)
        object.__setattr__(self, "session", session)
        object.__setattr__(self, "workspace", workspace)


@dataclass(frozen=True, slots=True, init=False)
class TaskRef:
    mode: AppMode
    owner: str
    session: str
    run: str
    workspace: str | None

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("TaskRef cannot be subclassed")

    @overload
    def __init__(
        self,
        *,
        mode: AppMode,
        owner: str,
        session: str,
        run: str,
        workspace: str | None = None,
    ) -> None: ...

    @overload
    def __init__(
        self,
        *,
        mode: str,
        owner: str,
        session: str,
        run: str,
        workspace: str | None = None,
    ) -> None: ...

    def __init__(
        self,
        *,
        mode: AppMode | str,
        owner: str,
        session: str,
        run: str,
        workspace: str | None = None,
    ) -> None:
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "owner", owner)
        object.__setattr__(self, "session", session)
        object.__setattr__(self, "run", run)
        object.__setattr__(self, "workspace", workspace)
        self.__post_init__()

    def __post_init__(self) -> None:
        raw_mode = cast(object, self.mode)
        mode = _coerce_app_mode(raw_mode)
        owner = _validate_identity(cast(object, self.owner), field="owner", pattern=_OWNER_RE, max_chars=192)
        session = _validate_identity(cast(object, self.session), field="session", pattern=_SESSION_RUN_RE, max_chars=192)
        run = _validate_identity(cast(object, self.run), field="run", pattern=_SESSION_RUN_RE, max_chars=192)
        workspace = _validate_workspace(cast(object, self.workspace), mode=mode)
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "owner", owner)
        object.__setattr__(self, "session", session)
        object.__setattr__(self, "run", run)
        object.__setattr__(self, "workspace", workspace)

    @classmethod
    def from_dict(cls, payload: object) -> TaskRef:
        data = _require_exact_dict(payload)
        _validate_schema_version(data["schema_version"])
        mode = app_mode_from_json(data["mode"])
        return TaskRef(
            mode=mode,
            owner=cast(str, data["owner"]),
            session=cast(str, data["session"]),
            run=cast(str, data["run"]),
            workspace=cast(str | None, data["workspace"]),
        )

    @property
    def legacy_product_id(self) -> str:
        return product_id_from_mode(self.mode)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": TASK_REF_SCHEMA_VERSION,
            "mode": self.mode.value,
            "owner": self.owner,
            "session": self.session,
            "run": self.run,
            "workspace": self.workspace,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def canonical_hash(self) -> str:
        return "sha256:" + hashlib.sha256(TASK_REF_HASH_DOMAIN + self.canonical_bytes()).hexdigest()


def task_ref_from_client_request_v1(
    request: ClientTaskRequestV1,
    *,
    authority: ResolvedTaskAuthorityV1,
    server_run_id: str,
) -> TaskRef:
    if type(request) is not ClientTaskRequestV1:
        raise TaskAuthorityError(
            code="invalid_request_authority",
            field=None,
            detail="client task request must be parsed before adaptation",
        )
    if type(authority) is not ResolvedTaskAuthorityV1:
        raise TaskAuthorityError(
            code="invalid_request_authority",
            field=None,
            detail="resolved task authority is required",
        )
    if request.mode is not authority.mode:
        raise TaskAuthorityError(
            code="mode_authority_conflict",
            field="mode",
            detail="requested mode does not match resolved authority",
        )
    if request.session is not None and request.session != authority.session:
        raise TaskAuthorityError(
            code="session_authority_conflict",
            field="session",
            detail="requested session does not match resolved authority",
        )
    if request.workspace != authority.workspace:
        raise TaskAuthorityError(
            code="workspace_authority_conflict",
            field="workspace",
            detail="requested workspace does not match resolved authority",
        )
    try:
        return TaskRef(
            mode=authority.mode,
            owner=authority.mode_runtime_owner,
            session=authority.session,
            run=server_run_id,
            workspace=authority.workspace,
        )
    except ModeContractError as exc:
        raise TaskAuthorityError(
            code=exc.code,
            field=exc.field,
            detail=exc.detail,
        ) from None


@dataclass(frozen=True, slots=True, init=False)
class ModeManifestV1:
    """Pure mode capability ceiling; it grants no authority or runtime state."""

    mode: AppMode
    feature_ids: tuple[str, ...]
    tool_ids: tuple[str, ...]
    connector_ids: tuple[str, ...]

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("ModeManifestV1 cannot be subclassed")

    def __init__(
        self,
        *,
        mode: AppMode,
        feature_ids: tuple[str, ...] = (),
        tool_ids: tuple[str, ...] = (),
        connector_ids: tuple[str, ...] = (),
    ) -> None:
        if type(mode) is not AppMode:
            raise _manifest_error(code="invalid_type", field="mode", detail="mode must be AppMode")
        features = _manifest_ids(cast("object", feature_ids), field="feature_ids", decoded=False)
        tools = _manifest_ids(cast("object", tool_ids), field="tool_ids", decoded=False)
        connectors = _manifest_ids(cast("object", connector_ids), field="connector_ids", decoded=False)
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "feature_ids", features)
        object.__setattr__(self, "tool_ids", tools)
        object.__setattr__(self, "connector_ids", connectors)

    @classmethod
    def from_dict(cls, payload: object) -> ModeManifestV1:
        data = _manifest_dict(payload)
        _manifest_schema(data["schema_version"])
        try:
            mode = app_mode_from_json(data["mode"])
        except ModeContractError as exc:
            raise _manifest_error(code=exc.code, field=exc.field, detail=exc.detail) from None
        features = _manifest_ids(data["feature_ids"], field="feature_ids", decoded=True)
        tools = _manifest_ids(data["tool_ids"], field="tool_ids", decoded=True)
        connectors = _manifest_ids(data["connector_ids"], field="connector_ids", decoded=True)
        required = data["workspace_required"]
        if type(required) is not bool:
            raise _manifest_error(
                code="invalid_type",
                field="workspace_required",
                detail="workspace_required must be a boolean",
            )
        expected = mode is AppMode.WORK
        if required is not expected:
            raise _manifest_error(
                code="workspace_requirement_mismatch",
                field="workspace_required",
                detail="workspace_required must be derived from mode",
            )
        return cls(mode=mode, feature_ids=features, tool_ids=tools, connector_ids=connectors)

    @property
    def schema_version(self) -> int:
        return MODE_MANIFEST_SCHEMA_VERSION

    @property
    def workspace_required(self) -> bool:
        return self.mode is AppMode.WORK

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "mode": self.mode.value,
            "feature_ids": list(self.feature_ids),
            "tool_ids": list(self.tool_ids),
            "connector_ids": list(self.connector_ids),
            "workspace_required": self.workspace_required,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def canonical_hash(self) -> str:
        return "sha256:" + hashlib.sha256(MODE_MANIFEST_HASH_DOMAIN + self.canonical_bytes()).hexdigest()

    def _check_operand(self, other: object) -> ModeManifestV1:
        if type(other) is not ModeManifestV1:
            raise _manifest_error(code="invalid_operand", field=None, detail="manifest operand is required")
        if self.mode is not other.mode:
            raise _manifest_error(code="mode_mismatch", field="mode", detail="manifest modes must match")
        return other

    def is_subset_of(self, other: object, /) -> bool:
        candidate = self._check_operand(other)
        return (
            set(self.feature_ids).issubset(candidate.feature_ids)
            and set(self.tool_ids).issubset(candidate.tool_ids)
            and set(self.connector_ids).issubset(candidate.connector_ids)
        )

    def intersect(self, other: object, /) -> ModeManifestV1:
        candidate = self._check_operand(other)
        return ModeManifestV1(
            mode=self.mode,
            feature_ids=tuple(sorted(set(self.feature_ids).intersection(candidate.feature_ids))),
            tool_ids=tuple(sorted(set(self.tool_ids).intersection(candidate.tool_ids))),
            connector_ids=tuple(sorted(set(self.connector_ids).intersection(candidate.connector_ids))),
        )

    def narrow(
        self,
        *,
        feature_ids: tuple[str, ...] | None = None,
        tool_ids: tuple[str, ...] | None = None,
        connector_ids: tuple[str, ...] | None = None,
    ) -> ModeManifestV1:
        values = (
            ("feature_ids", feature_ids, self.feature_ids),
            ("tool_ids", tool_ids, self.tool_ids),
            ("connector_ids", connector_ids, self.connector_ids),
        )
        narrowed: dict[str, tuple[str, ...]] = {}
        for field, replacement, current in values:
            if replacement is None:
                narrowed[field] = current
                continue
            candidate = _manifest_ids(cast("object", replacement), field=field, decoded=False)
            if not set(candidate).issubset(current):
                raise _manifest_error(
                    code="capability_widening",
                    field=field,
                    detail="narrowing cannot widen capabilities",
                )
            narrowed[field] = candidate
        return ModeManifestV1(
            mode=self.mode,
            feature_ids=narrowed["feature_ids"],
            tool_ids=narrowed["tool_ids"],
            connector_ids=narrowed["connector_ids"],
        )


@dataclass(frozen=True, slots=True, init=False)
class DirectoryGrantV1:
    """Pure directory authorization ceiling; grants no authority or runtime state."""

    mode: AppMode
    workspace: str | None
    root: str

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("DirectoryGrantV1 cannot be subclassed")

    def __init__(
        self,
        *,
        mode: AppMode,
        workspace: str | None,
        root: str,
    ) -> None:
        if type(mode) is not AppMode:
            raise _grant_error(code="invalid_type", field="mode", detail="mode must be AppMode")
        if mode is AppMode.PERSONAL:
            if workspace is not None:
                raise _grant_error(
                    code="workspace_mode_mismatch",
                    field="workspace",
                    detail="personal workspace must be null",
                )
        else:
            if type(workspace) is not str or not workspace:
                raise _grant_error(
                    code="workspace_mode_mismatch",
                    field="workspace",
                    detail="work workspace must be non-empty",
                )
            if _WORKSPACE_RE.fullmatch(workspace) is None:
                raise _grant_error(
                    code="invalid_value",
                    field="workspace",
                    detail="workspace must be an opaque handle",
                )
        validated_root = _grant_root(cast("object", root))
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "workspace", workspace)
        object.__setattr__(self, "root", validated_root)

    @classmethod
    def from_dict(cls, payload: object) -> DirectoryGrantV1:
        data = _grant_dict(payload)
        sv = data["schema_version"]
        if type(sv) is not int:
            raise _grant_error(code="invalid_type", field="schema_version", detail="schema_version must be 1")
        if sv != DIRECTORY_GRANT_SCHEMA_VERSION:
            raise _grant_error(code="invalid_value", field="schema_version", detail="schema_version must be 1")
        try:
            mode = app_mode_from_json(data["mode"])
        except ModeContractError as exc:
            raise _grant_error(code=exc.code, field=exc.field, detail=exc.detail) from None
        return cls(mode=mode, workspace=cast("str | None", data["workspace"]), root=cast("str", data["root"]))

    @property
    def schema_version(self) -> int:
        return DIRECTORY_GRANT_SCHEMA_VERSION

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "mode": self.mode.value,
            "workspace": self.workspace,
            "root": self.root,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def canonical_hash(self) -> str:
        return "sha256:" + hashlib.sha256(DIRECTORY_GRANT_HASH_DOMAIN + self.canonical_bytes()).hexdigest()

    def is_subset_of(self, other: object, /) -> bool:
        if type(other) is not DirectoryGrantV1:
            raise _grant_error(code="invalid_operand", field=None, detail="grant operand is required")
        if self.mode is not other.mode:
            raise _grant_error(code="mode_mismatch", field="mode", detail="grant modes must match")
        if self.workspace != other.workspace:
            return False
        if self.root == other.root:
            return True
        if other.root == "/":
            return True
        self_parts = self.root.split("/")
        other_parts = other.root.split("/")
        if len(self_parts) < len(other_parts):
            return False
        return self_parts[:len(other_parts)] == other_parts


# -- R1-D: AttentionItem and ArtifactRef (EchoLedger projections) --

_ATTENTION_ITEM_FIELDS: Final = frozenset({
    "schema_version", "kind", "mode", "owner", "session", "run",
    "workspace", "effect_digest", "args_digest", "eligible_approver", "ttl_seconds",
})
_ATTENTION_ITEM_FIELD_ORDER: Final = (
    "schema_version", "kind", "mode", "owner", "session", "run",
    "workspace", "effect_digest", "args_digest", "eligible_approver", "ttl_seconds",
)
_ATTENTION_KINDS: Final = frozenset({
    "approval", "question", "directory_grant", "plan_confirmation",
    "manual_review", "connector_authorization", "mobile_pairing",
    "friend_request", "notification", "memory_proposal",
})
_DIGEST_RE: Final = re.compile(r"^sha256:[0-9a-f]{64}$")


_ATTENTION_TTL_MAX: Final = 86400


def _attention_error(*, code: str, field: str | None, detail: str) -> AttentionItemValidationError:
    return AttentionItemValidationError(code=code, field=field, detail=detail)


def _attention_dict(payload: object) -> dict[str, object]:
    if type(payload) is not dict:
        raise _attention_error(code="invalid_root", field=None, detail="attention payload must be a dict")
    if any(type(key) is not str for key in payload):
        raise _attention_error(code="invalid_key", field=None, detail="attention keys must be strings")
    if set(payload) - _ATTENTION_ITEM_FIELDS:
        raise _attention_error(code="unknown_field", field=None, detail="attention contains unknown fields")
    for field in _ATTENTION_ITEM_FIELD_ORDER:
        if field not in payload:
            raise _attention_error(code="missing_field", field=field, detail="attention field is required")
    return cast("dict[str, object]", payload)


def _validate_digest(value: object, *, field: str) -> str:
    if type(value) is not str:
        raise _attention_error(code="invalid_type", field=field, detail=f"{field} must be text")
    if not _DIGEST_RE.fullmatch(value):
        raise _attention_error(code="invalid_value", field=field, detail=f"{field} must be sha256:hex64")
    return value


@dataclass(frozen=True, slots=True, init=False)
class AttentionItemV1:
    """Pure EchoLedger projection for unified inbox items."""

    kind: str
    mode: AppMode
    owner: str
    session: str
    run: str
    workspace: str | None
    effect_digest: str
    args_digest: str
    eligible_approver: str
    ttl_seconds: int

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("AttentionItemV1 cannot be subclassed")

    def __init__(self, *, kind: str, mode: AppMode, owner: str, session: str,
                 run: str, workspace: str | None, effect_digest: str,
                 args_digest: str, eligible_approver: str, ttl_seconds: int) -> None:
        if type(kind) is not str or kind not in _ATTENTION_KINDS:
            raise _attention_error(code="invalid_value", field="kind", detail="unknown attention kind")
        if type(mode) is not AppMode:
            raise _attention_error(code="invalid_type", field="mode", detail="mode must be AppMode")
        owner_val = _validate_identity(cast("object", owner), field="owner", pattern=_OWNER_RE, max_chars=192)
        session_val = _validate_identity(cast("object", session), field="session", pattern=_SESSION_RUN_RE, max_chars=192)
        run_val = _validate_identity(cast("object", run), field="run", pattern=_SESSION_RUN_RE, max_chars=192)
        ws_val = _validate_workspace(cast("object", workspace), mode=mode)
        eff = _validate_digest(effect_digest, field="effect_digest")
        args = _validate_digest(args_digest, field="args_digest")
        try:
            approver_val = _validate_identity(cast("object", eligible_approver), field="eligible_approver", pattern=_OWNER_RE, max_chars=192)
        except ModeContractError as exc:
            raise _attention_error(code=exc.code, field=exc.field, detail=exc.detail) from None
        if type(ttl_seconds) is not int or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
            raise _attention_error(code="invalid_value", field="ttl_seconds", detail="must be positive int")
        if ttl_seconds > _ATTENTION_TTL_MAX:
            raise _attention_error(code="invalid_value", field="ttl_seconds", detail="exceeds maximum")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "owner", owner_val)
        object.__setattr__(self, "session", session_val)
        object.__setattr__(self, "run", run_val)
        object.__setattr__(self, "workspace", ws_val)
        object.__setattr__(self, "effect_digest", eff)
        object.__setattr__(self, "args_digest", args)
        object.__setattr__(self, "eligible_approver", approver_val)
        object.__setattr__(self, "ttl_seconds", ttl_seconds)

    @property
    def schema_version(self) -> int:
        return ATTENTION_ITEM_SCHEMA_VERSION

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version, "kind": self.kind, "mode": self.mode.value,
            "owner": self.owner, "session": self.session, "run": self.run,
            "workspace": self.workspace, "effect_digest": self.effect_digest,
            "args_digest": self.args_digest, "eligible_approver": self.eligible_approver,
            "ttl_seconds": self.ttl_seconds,
        }

    @classmethod
    def from_dict(cls, payload: object) -> AttentionItemV1:
        data = _attention_dict(payload)
        sv = data["schema_version"]
        if type(sv) is not int or sv != ATTENTION_ITEM_SCHEMA_VERSION:
            raise _attention_error(code="invalid_type", field="schema_version", detail="schema_version must be 1")
        try:
            mode = app_mode_from_json(data["mode"])
        except ModeContractError as exc:
            raise _attention_error(code=exc.code, field=exc.field, detail=exc.detail) from None
        return cls(
            kind=cast("str", data["kind"]),
            mode=mode,
            owner=cast("str", data["owner"]),
            session=cast("str", data["session"]),
            run=cast("str", data["run"]),
            workspace=cast("str | None", data["workspace"]),
            effect_digest=cast("str", data["effect_digest"]),
            args_digest=cast("str", data["args_digest"]),
            eligible_approver=cast("str", data["eligible_approver"]),
            ttl_seconds=cast("int", data["ttl_seconds"]),
        )

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def canonical_hash(self) -> str:
        return "sha256:" + hashlib.sha256(ATTENTION_ITEM_HASH_DOMAIN + self.canonical_bytes()).hexdigest()


_ARTIFACT_REF_FIELDS: Final = frozenset({
    "schema_version", "mode", "owner", "session", "workspace", "kind", "uri", "digest", "acl", "created_by_run",
})
_ARTIFACT_REF_FIELD_ORDER: Final = (
    "schema_version", "mode", "owner", "session", "workspace", "kind", "uri", "digest", "acl", "created_by_run",
)
_ARTIFACT_KINDS: Final = frozenset({
    "document", "spreadsheet", "pdf", "image", "code_archive", "report", "download",
})
_ARTIFACT_URI_RE: Final = re.compile(r"^echo://[A-Za-z0-9][A-Za-z0-9._\-/]*$")


def _artifact_error(*, code: str, field: str | None, detail: str) -> ArtifactRefValidationError:
    return ArtifactRefValidationError(code=code, field=field, detail=detail)


def _artifact_dict(payload: object) -> dict[str, object]:
    if type(payload) is not dict:
        raise _artifact_error(code="invalid_root", field=None, detail="artifact payload must be a dict")
    if any(type(key) is not str for key in payload):
        raise _artifact_error(code="invalid_key", field=None, detail="artifact keys must be strings")
    if set(payload) - _ARTIFACT_REF_FIELDS:
        raise _artifact_error(code="unknown_field", field=None, detail="artifact contains unknown fields")
    for field in _ARTIFACT_REF_FIELD_ORDER:
        if field not in payload:
            raise _artifact_error(code="missing_field", field=field, detail="artifact field is required")
    return cast("dict[str, object]", payload)


def _artifact_schema(value: object) -> None:
    if type(value) is not int or value != ARTIFACT_REF_SCHEMA_VERSION:
        raise _artifact_error(code="invalid_type", field="schema_version", detail="schema_version must be 1")


@dataclass(frozen=True, slots=True, init=False)
class ArtifactRefV1:
    """Pure EchoLedger projection for unified artifact references."""

    mode: AppMode
    owner: str
    session: str
    workspace: str | None
    kind: str
    uri: str
    digest: str
    acl: str
    created_by_run: str

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("ArtifactRefV1 cannot be subclassed")

    def __init__(self, *, mode: AppMode, owner: str, session: str,
                 workspace: str | None, kind: str, uri: str, digest: str,
                 acl: str, created_by_run: str) -> None:
        if type(mode) is not AppMode:
            raise _artifact_error(code="invalid_type", field="mode", detail="mode must be AppMode")
        owner_val = _validate_identity(cast("object", owner), field="owner", pattern=_OWNER_RE, max_chars=192)
        session_val = _validate_identity(cast("object", session), field="session", pattern=_SESSION_RUN_RE, max_chars=192)
        ws_val = _validate_workspace(cast("object", workspace), mode=mode)
        try:
            run_val = _validate_identity(cast("object", created_by_run), field="created_by_run", pattern=_SESSION_RUN_RE, max_chars=192)
        except ModeContractError as exc:
            raise _artifact_error(code=exc.code, field=exc.field, detail=exc.detail) from None
        if type(kind) is not str or kind not in _ARTIFACT_KINDS:
            raise _artifact_error(code="invalid_value", field="kind", detail="unknown artifact kind")
        if type(uri) is not str or not uri or len(uri) > 4096:
            raise _artifact_error(code="invalid_value", field="uri", detail="uri is invalid")
        if unicodedata.normalize("NFC", uri) != uri:
            raise _artifact_error(code="noncanonical_unicode", field="uri", detail="uri must be NFC-normalized")
        if any(unicodedata.category(ch).startswith("C") for ch in uri):
            raise _artifact_error(code="invalid_value", field="uri", detail="uri has control characters")
        if _ARTIFACT_URI_RE.fullmatch(uri) is None:
            raise _artifact_error(code="invalid_value", field="uri", detail="uri must be an opaque echo:// reference")
        if type(digest) is not str or not _DIGEST_RE.fullmatch(digest):
            raise _artifact_error(code="invalid_value", field="digest", detail="digest must be sha256:hex64")
        if type(acl) is not str or acl not in ("private", "owner", "session", "workspace"):
            raise _artifact_error(code="invalid_value", field="acl", detail="unknown acl")
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "owner", owner_val)
        object.__setattr__(self, "session", session_val)
        object.__setattr__(self, "workspace", ws_val)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "uri", uri)
        object.__setattr__(self, "digest", digest)
        object.__setattr__(self, "acl", acl)
        object.__setattr__(self, "created_by_run", run_val)

    @property
    def schema_version(self) -> int:
        return ARTIFACT_REF_SCHEMA_VERSION

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version, "mode": self.mode.value,
            "owner": self.owner, "session": self.session, "workspace": self.workspace,
            "kind": self.kind, "uri": self.uri, "digest": self.digest, "acl": self.acl,
            "created_by_run": self.created_by_run,
        }

    @classmethod
    def from_dict(cls, payload: object) -> ArtifactRefV1:
        data = _artifact_dict(payload)
        _artifact_schema(data["schema_version"])
        try:
            mode = app_mode_from_json(data["mode"])
        except ModeContractError as exc:
            raise _artifact_error(code=exc.code, field=exc.field, detail=exc.detail) from None
        return cls(
            mode=mode,
            owner=cast("str", data["owner"]),
            session=cast("str", data["session"]),
            workspace=cast("str | None", data["workspace"]),
            kind=cast("str", data["kind"]),
            uri=cast("str", data["uri"]),
            digest=cast("str", data["digest"]),
            acl=cast("str", data["acl"]),
            created_by_run=cast("str", data["created_by_run"]),
        )

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def canonical_hash(self) -> str:
        return "sha256:" + hashlib.sha256(ARTIFACT_REF_HASH_DOMAIN + self.canonical_bytes()).hexdigest()


# -- R1-E: ConnectorManifest and ConnectionRef (pure schema) --

_CONNECTOR_MANIFEST_FIELDS: Final = frozenset({
    "schema_version", "connector_type", "capabilities", "read_scopes", "write_scopes", "approval_policy",
})
_CONNECTOR_MANIFEST_FIELD_ORDER: Final = (
    "schema_version", "connector_type", "capabilities", "read_scopes", "write_scopes", "approval_policy",
)
_CONNECTOR_APPROVAL_POLICIES: Final = frozenset({"never", "read_only", "always", "explicit"})


def _connector_error(*, code: str, field: str | None, detail: str) -> ConnectorManifestValidationError:
    return ConnectorManifestValidationError(code=code, field=field, detail=detail)


def _connector_dict(payload: object) -> dict[str, object]:
    if type(payload) is not dict:
        raise _connector_error(code="invalid_root", field=None, detail="connector payload must be a dict")
    if any(type(key) is not str for key in payload):
        raise _connector_error(code="invalid_key", field=None, detail="connector keys must be strings")
    if set(payload) - _CONNECTOR_MANIFEST_FIELDS:
        raise _connector_error(code="unknown_field", field=None, detail="connector contains unknown fields")
    for field in _CONNECTOR_MANIFEST_FIELD_ORDER:
        if field not in payload:
            raise _connector_error(code="missing_field", field=field, detail="connector field is required")
    return cast("dict[str, object]", payload)


def _validate_id_list(value: object, *, field: str, decoded: bool) -> tuple[str, ...]:
    return _manifest_ids(value, field=field, decoded=decoded)


@dataclass(frozen=True, slots=True, init=False)
class ConnectorManifestV1:
    """Pure connector capability declaration; no credentials or network."""

    connector_type: str
    capabilities: tuple[str, ...]
    read_scopes: tuple[str, ...]
    write_scopes: tuple[str, ...]
    approval_policy: str

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("ConnectorManifestV1 cannot be subclassed")

    def __init__(self, *, connector_type: str, capabilities: tuple[str, ...] = (),
                 read_scopes: tuple[str, ...] = (), write_scopes: tuple[str, ...] = (),
                 approval_policy: str = "always") -> None:
        if type(connector_type) is not str or not _MODE_MANIFEST_ID_RE.fullmatch(connector_type):
            raise _connector_error(code="invalid_value", field="connector_type", detail="invalid connector type")
        caps = _validate_id_list(cast("object", capabilities), field="capabilities", decoded=False)
        reads = _validate_id_list(cast("object", read_scopes), field="read_scopes", decoded=False)
        writes = _validate_id_list(cast("object", write_scopes), field="write_scopes", decoded=False)
        if type(approval_policy) is not str or approval_policy not in _CONNECTOR_APPROVAL_POLICIES:
            raise _connector_error(code="invalid_value", field="approval_policy", detail="unknown policy")
        if approval_policy in ("read_only", "never") and len(writes) > 0:
            raise _connector_error(
                code="policy_conflict", field="approval_policy",
                detail="read_only or never policy must not have write scopes",
            )
        object.__setattr__(self, "connector_type", connector_type)
        object.__setattr__(self, "capabilities", caps)
        object.__setattr__(self, "read_scopes", reads)
        object.__setattr__(self, "write_scopes", writes)
        object.__setattr__(self, "approval_policy", approval_policy)

    @property
    def schema_version(self) -> int:
        return CONNECTOR_MANIFEST_SCHEMA_VERSION

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version, "connector_type": self.connector_type,
            "capabilities": list(self.capabilities), "read_scopes": list(self.read_scopes),
            "write_scopes": list(self.write_scopes), "approval_policy": self.approval_policy,
        }

    @classmethod
    def from_dict(cls, payload: object) -> ConnectorManifestV1:
        data = _connector_dict(payload)
        sv = data["schema_version"]
        if type(sv) is not int or sv != CONNECTOR_MANIFEST_SCHEMA_VERSION:
            raise _connector_error(code="invalid_type", field="schema_version", detail="schema_version must be 1")
        caps = _validate_id_list(data["capabilities"], field="capabilities", decoded=True)
        reads = _validate_id_list(data["read_scopes"], field="read_scopes", decoded=True)
        writes = _validate_id_list(data["write_scopes"], field="write_scopes", decoded=True)
        policy = data["approval_policy"]
        if type(policy) is not str or policy not in _CONNECTOR_APPROVAL_POLICIES:
            raise _connector_error(code="invalid_value", field="approval_policy", detail="unknown policy")
        if policy in ("read_only", "never") and len(writes) > 0:
            raise _connector_error(
                code="policy_conflict", field="approval_policy",
                detail="read_only or never policy must not have write scopes",
            )
        return cls(
            connector_type=cast("str", data["connector_type"]),
            capabilities=caps,
            read_scopes=reads,
            write_scopes=writes,
            approval_policy=policy,
        )

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def canonical_hash(self) -> str:
        return "sha256:" + hashlib.sha256(CONNECTOR_MANIFEST_HASH_DOMAIN + self.canonical_bytes()).hexdigest()


_CONNECTION_REF_FIELDS: Final = frozenset({
    "schema_version", "mode", "owner", "workspace", "connector_type", "connection_id", "authorized_by",
})
_CONNECTION_REF_FIELD_ORDER: Final = (
    "schema_version", "mode", "owner", "workspace", "connector_type", "connection_id", "authorized_by",
)


def _connection_error(*, code: str, field: str | None, detail: str) -> ConnectionRefValidationError:
    return ConnectionRefValidationError(code=code, field=field, detail=detail)


def _connection_dict(payload: object) -> dict[str, object]:
    if type(payload) is not dict:
        raise _connection_error(code="invalid_root", field=None, detail="connection payload must be a dict")
    if any(type(key) is not str for key in payload):
        raise _connection_error(code="invalid_key", field=None, detail="connection keys must be strings")
    if set(payload) - _CONNECTION_REF_FIELDS:
        raise _connection_error(code="unknown_field", field=None, detail="connection contains unknown fields")
    for field in _CONNECTION_REF_FIELD_ORDER:
        if field not in payload:
            raise _connection_error(code="missing_field", field=field, detail="connection field is required")
    return cast("dict[str, object]", payload)


@dataclass(frozen=True, slots=True, init=False)
class ConnectionRefV1:
    """Pure authorized connection reference; no credentials."""

    mode: AppMode
    owner: str
    workspace: str | None
    connector_type: str
    connection_id: str
    authorized_by: str

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("ConnectionRefV1 cannot be subclassed")

    def __init__(self, *, mode: AppMode, owner: str, workspace: str | None,
                 connector_type: str, connection_id: str, authorized_by: str) -> None:
        if type(mode) is not AppMode:
            raise _connection_error(code="invalid_type", field="mode", detail="mode must be AppMode")
        owner_val = _validate_identity(cast("object", owner), field="owner", pattern=_OWNER_RE, max_chars=192)
        ws_val = _validate_workspace(cast("object", workspace), mode=mode)
        if type(connector_type) is not str or not _MODE_MANIFEST_ID_RE.fullmatch(connector_type):
            raise _connection_error(code="invalid_value", field="connector_type", detail="invalid connector type")
        try:
            conn_id_val = _validate_identity(cast("object", connection_id), field="connection_id", pattern=_SESSION_RUN_RE, max_chars=256)
            auth_by_val = _validate_identity(cast("object", authorized_by), field="authorized_by", pattern=_OWNER_RE, max_chars=192)
        except ModeContractError as exc:
            raise _connection_error(code=exc.code, field=exc.field, detail=exc.detail) from None
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "owner", owner_val)
        object.__setattr__(self, "workspace", ws_val)
        object.__setattr__(self, "connector_type", connector_type)
        object.__setattr__(self, "connection_id", conn_id_val)
        object.__setattr__(self, "authorized_by", auth_by_val)

    @property
    def schema_version(self) -> int:
        return CONNECTION_REF_SCHEMA_VERSION

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version, "mode": self.mode.value,
            "owner": self.owner, "workspace": self.workspace,
            "connector_type": self.connector_type, "connection_id": self.connection_id,
            "authorized_by": self.authorized_by,
        }

    @classmethod
    def from_dict(cls, payload: object) -> ConnectionRefV1:
        data = _connection_dict(payload)
        sv = data["schema_version"]
        if type(sv) is not int or sv != CONNECTION_REF_SCHEMA_VERSION:
            raise _connection_error(code="invalid_type", field="schema_version", detail="schema_version must be 1")
        try:
            mode = app_mode_from_json(data["mode"])
        except ModeContractError as exc:
            raise _connection_error(code=exc.code, field=exc.field, detail=exc.detail) from None
        return cls(
            mode=mode,
            owner=cast("str", data["owner"]),
            workspace=cast("str | None", data["workspace"]),
            connector_type=cast("str", data["connector_type"]),
            connection_id=cast("str", data["connection_id"]),
            authorized_by=cast("str", data["authorized_by"]),
        )

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def canonical_hash(self) -> str:
        return "sha256:" + hashlib.sha256(CONNECTION_REF_HASH_DOMAIN + self.canonical_bytes()).hexdigest()
