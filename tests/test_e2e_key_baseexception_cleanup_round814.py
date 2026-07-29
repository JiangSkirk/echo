from __future__ import annotations

import errno
import gc
import os
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from js.echo.ledger import e2e_signing
from js.echo.ledger.e2e_signing import (
    assert_no_private_key_under,
    destroy_private_key,
    open_private_key_bytes,
    prepare_ephemeral_keypair,
)


def _setup(tmp_path: Path) -> tuple[Path, Path, Path]:
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    keys_parent = tmp_path / "external-keys"
    (repo / "docs" / "security").mkdir(parents=True)
    evidence.mkdir()
    keys_parent.mkdir()
    os.chmod(keys_parent, 0o700)
    return repo, evidence, keys_parent


def _private_keys(root: Path) -> list[Path]:
    return [path for path in root.rglob("ledger.ed25519.private") if path.is_file()]


def _exception_tree(exc: BaseException) -> list[BaseException]:
    nodes = [exc]
    if isinstance(exc, BaseExceptionGroup):
        for child in exc.exceptions:
            nodes.extend(_exception_tree(child))
    return nodes


def _exception_graph(exc: BaseException) -> list[BaseException]:
    pending = [exc]
    seen: set[int] = set()
    nodes: list[BaseException] = []
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        nodes.append(current)
        if isinstance(current, BaseExceptionGroup):
            pending.extend(current.exceptions)
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return nodes


def _assert_exception_sanitized(exc: BaseException, *secrets: str) -> None:
    nodes = _exception_graph(exc)
    rendered = "\n".join(
        [str(node) for node in nodes]
        + [repr(node) for node in nodes]
        + ["".join(traceback.format_exception(exc))]
    )
    for secret in secrets:
        assert secret not in rendered
    for node in nodes:
        if isinstance(node, OSError):
            assert node.filename is None or str(node.filename) not in secrets


def _assert_closed(fd: int) -> None:
    with pytest.raises(OSError) as caught:
        os.fstat(fd)
    assert caught.value.errno == errno.EBADF


def _capture_failure(action: Callable[[], object]) -> BaseException:
    try:
        action()
    except BaseException as exc:
        return exc
    raise AssertionError("expected operation to fail")


@pytest.mark.parametrize("primary_type", [KeyboardInterrupt, SystemExit])
def test_prepare_baseexception_rolls_back_private_key_and_closes_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    primary_type: type[BaseException],
) -> None:
    repo, evidence, keys_parent = _setup(tmp_path)
    opened_dir_fds: list[int] = []
    real_open = os.open
    primary = primary_type("PREPARE_ABORTED")

    def tracking_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if kwargs.get("dir_fd") is None and Path(path).name.startswith("js-e2e-ledger-"):
            opened_dir_fds.append(fd)
        return fd

    def abort_pubkey_write(root: Path, public_raw: bytes) -> dict[str, object]:
        raise primary

    monkeypatch.setattr(os, "open", tracking_open)
    monkeypatch.setattr(e2e_signing, "write_frozen_pubkey", abort_pubkey_write)

    observed = _capture_failure(
        lambda: prepare_ephemeral_keypair(repo, evidence_root=evidence, keys_parent=keys_parent)
    )
    residual = _private_keys(keys_parent)
    leftovers = list(keys_parent.iterdir())
    monkeypatch.undo()
    for path in residual:
        path.unlink(missing_ok=True)
        try:
            path.parent.rmdir()
        except OSError:
            pass

    assert observed is primary
    assert residual == []
    assert leftovers == []
    assert len(opened_dir_fds) == 1
    _assert_closed(opened_dir_fds[0])


@pytest.mark.parametrize(
    ("primary_type", "expected_group_type"),
    [
        (RuntimeError, ExceptionGroup),
        (KeyboardInterrupt, BaseExceptionGroup),
        (SystemExit, BaseExceptionGroup),
    ],
)
def test_prepare_primary_and_rollback_failure_use_correct_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    primary_type: type[BaseException],
    expected_group_type: type[BaseExceptionGroup],
) -> None:
    repo, evidence, keys_parent = _setup(tmp_path)
    primary = primary_type("PRIMARY_PREPARE_FAILURE")
    real_unlink = os.unlink

    def abort_pubkey_write(root: Path, public_raw: bytes) -> dict[str, object]:
        raise primary

    def fail_private_unlink(path, *args, **kwargs):
        if Path(path).name == "ledger.ed25519.private":
            raise OSError("ROLLBACK_UNLINK_FAILURE")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(e2e_signing, "write_frozen_pubkey", abort_pubkey_write)
    monkeypatch.setattr(os, "unlink", fail_private_unlink)

    observed = _capture_failure(
        lambda: prepare_ephemeral_keypair(repo, evidence_root=evidence, keys_parent=keys_parent)
    )
    monkeypatch.undo()
    residual = _private_keys(keys_parent)
    private_hex = [path.read_bytes().hex() for path in residual]
    for path in residual:
        path.unlink(missing_ok=True)
        try:
            path.parent.rmdir()
        except OSError:
            pass

    assert type(observed) is expected_group_type
    tree = _exception_tree(observed)
    assert tree[1] is primary
    assert any("ROLLBACK_UNLINK_FAILURE" in str(item) for item in tree)
    rendered = "\n".join([str(item) for item in tree] + [repr(observed)])
    assert str(keys_parent) not in rendered
    assert all(secret not in rendered for secret in private_hex)
    _assert_exception_sanitized(observed, str(keys_parent), *private_hex)


@pytest.mark.parametrize("primary_type", [KeyboardInterrupt, SystemExit])
def test_prepare_prehandle_baseexception_closes_both_fds_and_removes_residue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    primary_type: type[BaseException],
) -> None:
    repo, evidence, keys_parent = _setup(tmp_path)
    primary = primary_type("PREHANDLE_ABORTED")
    real_open = os.open
    opened_fds: list[int] = []

    def tracking_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        opened_fds.append(fd)
        return fd

    def abort_private_write(fd: int, data: bytes) -> None:
        raise primary

    monkeypatch.setattr(os, "open", tracking_open)
    monkeypatch.setattr(e2e_signing, "_pwrite_private_key", abort_private_write)

    observed = _capture_failure(
        lambda: prepare_ephemeral_keypair(repo, evidence_root=evidence, keys_parent=keys_parent)
    )

    assert observed is primary
    assert len(opened_fds) == 2
    for fd in opened_fds:
        _assert_closed(fd)
    assert _private_keys(keys_parent) == []
    assert list(keys_parent.iterdir()) == []


@pytest.mark.parametrize("primary_type", [KeyboardInterrupt, SystemExit])
def test_prepare_interrupt_between_handle_construction_and_transfer_has_one_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    primary_type: type[BaseException],
) -> None:
    repo, evidence, keys_parent = _setup(tmp_path)
    primary = primary_type("HANDOFF_ABORTED")
    real_handle_type = e2e_signing.EphemeralKeyHandle
    real_open = os.open
    real_close = os.close
    created_handles: list[Any] = []
    directory_fds: list[int] = []
    directory_close_calls: dict[int, int] = {}
    unlink_calls = 0
    real_unlink = os.unlink

    def tracking_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if kwargs.get("dir_fd") is None and Path(path).name.startswith("js-e2e-ledger-"):
            directory_fds.append(fd)
        return fd

    def tracking_close(fd: int) -> None:
        if fd in directory_fds:
            directory_close_calls[fd] = directory_close_calls.get(fd, 0) + 1
        real_close(fd)

    def tracking_unlink(path, *args, **kwargs):
        nonlocal unlink_calls
        if Path(path).name == "ledger.ed25519.private":
            unlink_calls += 1
        return real_unlink(path, *args, **kwargs)

    def interrupting_handle_constructor(**kwargs):
        created_handles.append(real_handle_type(**kwargs))
        raise primary

    monkeypatch.setattr(os, "open", tracking_open)
    monkeypatch.setattr(os, "close", tracking_close)
    monkeypatch.setattr(os, "unlink", tracking_unlink)
    monkeypatch.setattr(e2e_signing, "EphemeralKeyHandle", interrupting_handle_constructor)

    observed = _capture_failure(
        lambda: prepare_ephemeral_keypair(repo, evidence_root=evidence, keys_parent=keys_parent)
    )
    created_handles.clear()
    gc.collect()

    assert observed is primary
    assert len(directory_fds) == 1
    assert directory_close_calls == {directory_fds[0]: 1}
    assert unlink_calls == 1
    _assert_closed(directory_fds[0])
    assert _private_keys(keys_parent) == []
    assert list(keys_parent.iterdir()) == []


@pytest.mark.parametrize("primary_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("fault_side", ["before", "after"])
def test_prepare_interrupt_on_either_side_of_ownership_transfer_has_one_working_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    primary_type: type[BaseException],
    fault_side: str,
) -> None:
    repo, evidence, keys_parent = _setup(tmp_path)
    primary = primary_type(f"HANDOFF_{fault_side.upper()}_ABORTED")
    real_handle_type = e2e_signing.EphemeralKeyHandle
    real_open = os.open
    real_close = os.close
    real_unlink = os.unlink
    created_handles: list[Any] = []
    directory_fds: list[int] = []
    directory_close_calls: dict[int, int] = {}
    unlink_calls = 0

    class InterruptingOwnershipHandle(real_handle_type):
        _fault_armed = False

        def __setattr__(self, name: str, value: object) -> None:
            if name == "_owns_dir_fd" and value is True and self._fault_armed:
                if fault_side == "before":
                    raise primary
                super().__setattr__(name, value)
                raise primary
            super().__setattr__(name, value)

    def interruptible_handle_constructor(**kwargs):
        created = InterruptingOwnershipHandle(**kwargs)
        created._fault_armed = True
        created_handles.append(created)
        return created

    def tracking_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if kwargs.get("dir_fd") is None and Path(path).name.startswith("js-e2e-ledger-"):
            directory_fds.append(fd)
        return fd

    def tracking_close(fd: int) -> None:
        if fd in directory_fds:
            directory_close_calls[fd] = directory_close_calls.get(fd, 0) + 1
        real_close(fd)

    def tracking_unlink(path, *args, **kwargs):
        nonlocal unlink_calls
        if Path(path).name == "ledger.ed25519.private":
            unlink_calls += 1
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", tracking_open)
    monkeypatch.setattr(os, "close", tracking_close)
    monkeypatch.setattr(os, "unlink", tracking_unlink)
    monkeypatch.setattr(e2e_signing, "EphemeralKeyHandle", interruptible_handle_constructor)

    observed = _capture_failure(
        lambda: prepare_ephemeral_keypair(repo, evidence_root=evidence, keys_parent=keys_parent)
    )
    observed.__traceback__ = None
    created_handles.clear()
    gc.collect()
    residual = _private_keys(keys_parent)
    leftovers = list(keys_parent.iterdir())

    try:
        assert observed is primary
        assert len(directory_fds) == 1
        assert directory_close_calls == {directory_fds[0]: 1}
        assert unlink_calls == 1
        _assert_closed(directory_fds[0])
        assert residual == []
        assert leftovers == []
    finally:
        monkeypatch.undo()
        for fd in directory_fds:
            try:
                os.fstat(fd)
            except OSError as exc:
                if exc.errno == errno.EBADF:
                    continue
                raise
            real_close(fd)
        for path in residual:
            path.unlink(missing_ok=True)
        for path in leftovers:
            if path.is_dir():
                try:
                    path.rmdir()
                except OSError:
                    pass


def test_open_validation_close_errors_are_terminal_unknown_without_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, evidence, keys_parent = _setup(tmp_path)
    handle, _pubkey, _provenance = prepare_ephemeral_keypair(
        repo, evidence_root=evidence, keys_parent=keys_parent
    )
    os.chmod(handle.path, 0o640)
    real_open = os.open
    real_close = os.close
    validation_fds: list[int] = []
    close_attempts: dict[int, int] = {}

    def tracking_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        validation_fds.append(fd)
        return fd

    def fail_validation_closes(fd: int) -> None:
        if fd in validation_fds:
            close_attempts[fd] = close_attempts.get(fd, 0) + 1
            label = "KEY_CLOSE_FAILURE" if fd == validation_fds[-1] else "DIR_CLOSE_FAILURE"
            raise OSError(label)
        real_close(fd)

    monkeypatch.setattr(os, "open", tracking_open)
    monkeypatch.setattr(os, "close", fail_validation_closes)

    with pytest.raises(ExceptionGroup) as caught:
        open_private_key_bytes(handle.path)

    assert len(validation_fds) == 2
    assert close_attempts == dict.fromkeys(validation_fds, 1)
    for fd in validation_fds:
        os.fstat(fd)
    tree = _exception_tree(caught.value)
    assert any(isinstance(item, PermissionError) and "mode 0600" in str(item) for item in tree)
    assert any("KEY_CLOSE_FAILURE" in str(item) for item in tree)
    assert any("DIR_CLOSE_FAILURE" in str(item) for item in tree)
    assert "residual" in str(caught.value) or "uncertain" in str(caught.value)
    rendered = "\n".join(str(item) for item in tree)
    assert str(keys_parent) not in rendered
    monkeypatch.undo()
    for fd in validation_fds:
        real_close(fd)
    os.chmod(handle.path, 0o600)
    destroy_private_key(handle)


@pytest.mark.parametrize("primary_type", [KeyboardInterrupt, SystemExit])
def test_open_validation_baseexception_closes_key_and_directory_fds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    primary_type: type[BaseException],
) -> None:
    repo, evidence, keys_parent = _setup(tmp_path)
    handle, _pubkey, _provenance = prepare_ephemeral_keypair(
        repo, evidence_root=evidence, keys_parent=keys_parent
    )
    primary = primary_type("OPEN_VALIDATION_ABORTED")
    real_open = os.open
    validation_fds: list[int] = []

    def tracking_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        validation_fds.append(fd)
        return fd

    def abort_read(fd: int, size: int) -> bytes:
        raise primary

    monkeypatch.setattr(os, "open", tracking_open)
    monkeypatch.setattr(os, "read", abort_read)

    observed = _capture_failure(lambda: open_private_key_bytes(handle.path))

    assert observed is primary
    assert len(validation_fds) == 2
    for fd in validation_fds:
        _assert_closed(fd)
    monkeypatch.undo()
    destroy_private_key(handle)


def test_private_key_location_errors_do_not_expose_absolute_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    (repo / "docs" / "security").mkdir(parents=True)
    private_dir = repo / "private-location-canary"

    def controlled_mkdtemp(*args, **kwargs) -> str:
        private_dir.mkdir()
        return str(private_dir)

    monkeypatch.setattr(e2e_signing.tempfile, "mkdtemp", controlled_mkdtemp)

    observed = _capture_failure(lambda: prepare_ephemeral_keypair(repo))

    assert isinstance(observed, RuntimeError)
    assert str(private_dir) not in str(observed)


def test_private_key_leak_error_does_not_expose_absolute_path(tmp_path: Path) -> None:
    leaked = tmp_path / "evidence" / "private" / "ledger.ed25519.private"
    leaked.parent.mkdir(parents=True)
    leaked.write_bytes(b"x" * 32)

    observed = _capture_failure(lambda: assert_no_private_key_under(tmp_path / "evidence"))

    assert isinstance(observed, RuntimeError)
    assert str(leaked) not in str(observed)


@pytest.mark.parametrize("operation", ["mkdir", "chmod", "mkdtemp", "dir_open"])
def test_prepare_raw_filesystem_errors_have_sanitized_exception_graph(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    repo = tmp_path / "repo"
    (repo / "docs" / "security").mkdir(parents=True)
    keys_parent = tmp_path / "private-parent-canary"
    private_canary = keys_parent / "secret-key-location"
    real_mkdir = Path.mkdir
    real_chmod = os.chmod
    real_open = os.open

    if operation != "mkdir":
        keys_parent.mkdir()
        os.chmod(keys_parent, 0o700)

    def fail_mkdir(self: Path, *args, **kwargs) -> None:
        if self == keys_parent:
            raise OSError(errno.EACCES, "MKDIR_FAILED", str(private_canary))
        real_mkdir(self, *args, **kwargs)

    def fail_chmod(path, mode, *args, **kwargs) -> None:
        if Path(path) == keys_parent:
            raise OSError(errno.EACCES, "CHMOD_FAILED", str(private_canary))
        real_chmod(path, mode, *args, **kwargs)

    def fail_mkdtemp(*args, **kwargs) -> str:
        raise OSError(errno.EACCES, "MKDTEMP_FAILED", str(private_canary))

    def fail_dir_open(path, flags, *args, **kwargs):
        if kwargs.get("dir_fd") is None and Path(path).name.startswith("js-e2e-ledger-"):
            raise OSError(errno.EACCES, "DIR_OPEN_FAILED", str(path))
        return real_open(path, flags, *args, **kwargs)

    if operation == "mkdir":
        monkeypatch.setattr(Path, "mkdir", fail_mkdir)
    elif operation == "chmod":
        monkeypatch.setattr(os, "chmod", fail_chmod)
    elif operation == "mkdtemp":
        monkeypatch.setattr(e2e_signing.tempfile, "mkdtemp", fail_mkdtemp)
    else:
        monkeypatch.setattr(os, "open", fail_dir_open)

    observed = _capture_failure(lambda: prepare_ephemeral_keypair(repo, keys_parent=keys_parent))

    _assert_exception_sanitized(observed, str(keys_parent), str(private_canary))


def test_prepare_primary_cleanup_group_sanitizes_rmdir_and_ambient_chains(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, evidence, keys_parent = _setup(tmp_path)
    private_canary = keys_parent / "private-chain-canary"
    unsafe_cause = OSError(errno.EIO, "AMBIENT_PRIVATE_PATH", str(private_canary))
    primary = RuntimeError("SAFE_PRIMARY")
    primary.__cause__ = unsafe_cause
    primary.__suppress_context__ = True
    real_rmdir = Path.rmdir

    def abort_pubkey_write(root: Path, public_raw: bytes) -> dict[str, object]:
        raise primary

    def fail_private_rmdir(self: Path) -> None:
        if self.name.startswith("js-e2e-ledger-"):
            raise OSError(errno.EIO, "RMDIR_FAILED", str(self))
        real_rmdir(self)

    monkeypatch.setattr(e2e_signing, "write_frozen_pubkey", abort_pubkey_write)
    monkeypatch.setattr(Path, "rmdir", fail_private_rmdir)

    observed = _capture_failure(
        lambda: prepare_ephemeral_keypair(repo, evidence_root=evidence, keys_parent=keys_parent)
    )
    private_dirs = list(keys_parent.iterdir())

    assert type(observed) is ExceptionGroup
    assert observed.exceptions[0] is primary
    assert sum(item is primary for item in observed.exceptions) == 1
    assert observed.__cause__ is None
    assert observed.__context__ is None
    assert primary.__cause__ is None
    assert primary.__context__ is None
    _assert_exception_sanitized(
        observed,
        str(keys_parent),
        str(private_canary),
        *(str(path) for path in private_dirs),
    )


def test_open_parent_failure_has_sanitized_exception_graph(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private_parent = tmp_path / "open-private-parent-canary"
    private_parent.mkdir()
    os.chmod(private_parent, 0o700)
    private_path = private_parent / "ledger.ed25519.private"

    def fail_open(path, flags, *args, **kwargs):
        raise OSError(errno.EACCES, "OPEN_PARENT_FAILED", str(private_path))

    monkeypatch.setattr(os, "open", fail_open)

    observed = _capture_failure(lambda: open_private_key_bytes(private_path))

    _assert_exception_sanitized(observed, str(private_parent), str(private_path))


def test_handle_close_before_real_close_becomes_terminal_unknown_without_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, evidence, keys_parent = _setup(tmp_path)
    handle, _pubkey, _provenance = prepare_ephemeral_keypair(
        repo, evidence_root=evidence, keys_parent=keys_parent
    )
    real_close = os.close
    close_attempts = 0

    def fail_before_close(fd: int) -> None:
        nonlocal close_attempts
        if fd == handle._dir_fd:
            close_attempts += 1
            raise OSError("HANDLE_CLOSE_FAILED_BEFORE_CLOSE")
        real_close(fd)

    monkeypatch.setattr(os, "close", fail_before_close)

    observed = _capture_failure(handle.close)
    os.fstat(handle._dir_fd)
    retry = _capture_failure(handle.close)

    assert isinstance(observed, OSError)
    assert getattr(handle, "_close_state", None) == "unknown"
    assert not handle._closed
    assert not handle._owns_dir_fd
    assert close_attempts == 1
    assert isinstance(retry, RuntimeError)
    assert "unknown" in str(retry)
    monkeypatch.undo()
    real_close(handle._dir_fd)
    handle.path.unlink(missing_ok=True)
    try:
        handle.path.parent.rmdir()
    except OSError:
        pass


@pytest.mark.parametrize("primary_type", [KeyboardInterrupt, SystemExit])
def test_destroy_baseexception_and_close_failure_preserve_both_and_close_key_fd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    primary_type: type[BaseException],
) -> None:
    repo, evidence, keys_parent = _setup(tmp_path)
    handle, _pubkey, _provenance = prepare_ephemeral_keypair(
        repo, evidence_root=evidence, keys_parent=keys_parent
    )
    primary = primary_type("DESTROY_ABORTED")
    real_open = os.open
    real_close = os.close
    real_fstat = os.fstat
    key_fds: list[int] = []
    handle_close_attempts = 0
    validation_aborted = False

    def tracking_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if kwargs.get("dir_fd") == handle._dir_fd:
            key_fds.append(fd)
        return fd

    def abort_key_validation(fd: int) -> Any:
        nonlocal validation_aborted
        if fd in key_fds and not validation_aborted:
            validation_aborted = True
            raise primary
        return real_fstat(fd)

    def fail_handle_close(fd: int) -> None:
        nonlocal handle_close_attempts
        if fd == handle._dir_fd:
            handle_close_attempts += 1
            raise OSError("HANDLE_CLOSE_FAILURE")
        real_close(fd)

    monkeypatch.setattr(os, "open", tracking_open)
    monkeypatch.setattr(os, "fstat", abort_key_validation)
    monkeypatch.setattr(os, "close", fail_handle_close)

    observed = _capture_failure(lambda: destroy_private_key(handle))

    assert type(observed) is BaseExceptionGroup
    tree = _exception_tree(observed)
    assert tree[1] is primary
    assert any("HANDLE_CLOSE_FAILURE" in str(item) for item in tree)
    assert len(key_fds) == 1
    _assert_closed(key_fds[0])
    assert handle_close_attempts == 1
    assert getattr(handle, "_close_state", None) == "unknown"
    assert not handle._closed
    assert not handle._owns_dir_fd
    os.fstat(handle._dir_fd)
    assert "residual" in str(observed) or "uncertain" in str(observed)
    rendered = "\n".join(str(item) for item in tree)
    assert str(keys_parent) not in rendered
    monkeypatch.undo()
    real_close(handle._dir_fd)
    handle.path.unlink(missing_ok=True)
    try:
        handle.path.parent.rmdir()
    except OSError:
        pass


@pytest.mark.parametrize(
    "primary_factory",
    [
        lambda private_path: KeyboardInterrupt("KEY_FD_PROBE_ABORTED"),
        lambda private_path: SystemExit("KEY_FD_PROBE_ABORTED"),
        lambda private_path: OSError(errno.EIO, "KEY_FD_PROBE_FAILED", str(private_path)),
    ],
)
def test_prepare_new_key_fd_probe_failure_closes_fd_and_removes_residue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    primary_factory: Callable[[Path], BaseException],
) -> None:
    repo, evidence, keys_parent = _setup(tmp_path)
    real_open = os.open
    real_fstat = os.fstat
    key_fds: list[int] = []
    primary: BaseException | None = None

    def tracking_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if kwargs.get("dir_fd") is not None and Path(path).name == "ledger.ed25519.private":
            key_fds.append(fd)
        return fd

    def fail_initial_key_probe(fd: int) -> Any:
        nonlocal primary
        if fd in key_fds and primary is None:
            private_path = keys_parent / "private-probe-canary" / "ledger.ed25519.private"
            primary = primary_factory(private_path)
            raise primary
        return real_fstat(fd)

    monkeypatch.setattr(os, "open", tracking_open)
    monkeypatch.setattr(os, "fstat", fail_initial_key_probe)

    observed = _capture_failure(
        lambda: prepare_ephemeral_keypair(repo, evidence_root=evidence, keys_parent=keys_parent)
    )

    assert len(key_fds) == 1
    _assert_closed(key_fds[0])
    assert _private_keys(keys_parent) == []
    assert list(keys_parent.iterdir()) == []
    assert primary is not None
    if isinstance(primary, OSError):
        _assert_exception_sanitized(
            observed,
            str(keys_parent),
            str(primary.filename),
        )
    else:
        assert observed is primary


def test_handle_close_error_never_probes_or_retries_numeric_fd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, evidence, keys_parent = _setup(tmp_path)
    handle, _pubkey, _provenance = prepare_ephemeral_keypair(
        repo, evidence_root=evidence, keys_parent=keys_parent
    )
    real_close = os.close
    real_fstat = os.fstat
    close_primary = OSError("HANDLE_CLOSE_PRIMARY")
    close_attempts = 0
    forbidden_probe_calls = 0

    def fail_close(fd: int) -> None:
        nonlocal close_attempts
        if fd == handle._dir_fd:
            close_attempts += 1
            raise close_primary
        real_close(fd)

    def forbid_probe(fd: int) -> Any:
        nonlocal forbidden_probe_calls
        if fd == handle._dir_fd and close_attempts:
            forbidden_probe_calls += 1
            raise AssertionError("close-error descriptor must not be probed")
        return real_fstat(fd)

    monkeypatch.setattr(os, "close", fail_close)
    monkeypatch.setattr(os, "fstat", forbid_probe)

    observed = _capture_failure(handle.close)
    retry = _capture_failure(handle.close)

    assert observed is close_primary
    assert forbidden_probe_calls == 0
    assert close_attempts == 1
    assert getattr(handle, "_close_state", None) == "unknown"
    assert isinstance(retry, RuntimeError)
    assert "unknown" in str(retry)
    monkeypatch.undo()
    real_close(handle._dir_fd)
    handle.path.unlink(missing_ok=True)
    try:
        handle.path.parent.rmdir()
    except OSError:
        pass


def test_handle_close_before_real_close_unknown_state_never_closes_reused_fd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, evidence, keys_parent = _setup(tmp_path)
    handle, _pubkey, _provenance = prepare_ephemeral_keypair(
        repo, evidence_root=evidence, keys_parent=keys_parent
    )
    original_fd = handle._dir_fd
    original_path = handle.path
    decoy = tmp_path / "decoy-reused-fd"
    decoy.mkdir()
    os.chmod(decoy, 0o700)
    real_close = os.close
    real_open = os.open
    close_calls = 0

    def fail_before_close(fd: int) -> None:
        nonlocal close_calls
        if fd == original_fd:
            close_calls += 1
            raise OSError("HANDLE_CLOSE_BEFORE_REAL_CLOSE")
        real_close(fd)

    monkeypatch.setattr(os, "close", fail_before_close)

    observed = _capture_failure(handle.close)
    assert isinstance(observed, OSError)
    assert getattr(handle, "_close_state", None) == "unknown"
    assert close_calls == 1

    # External actor releases the original and reuses the same number.
    real_close(original_fd)
    decoy_fd = real_open(str(decoy), e2e_signing._dir_open_flags())
    if decoy_fd != original_fd:
        os.dup2(decoy_fd, original_fd)
        real_close(decoy_fd)
    reused_st = os.fstat(original_fd)
    assert (int(reused_st.st_dev), int(reused_st.st_ino)) != (
        handle._parent_dev,
        handle._parent_ino,
    )
    retry = _capture_failure(handle.close)
    assert isinstance(retry, RuntimeError)
    assert "unknown" in str(retry)
    assert not handle._closed
    assert not handle._owns_dir_fd
    assert close_calls == 1

    del handle
    gc.collect()

    os.fstat(original_fd)
    assert close_calls == 1
    monkeypatch.undo()
    real_close(original_fd)
    original_path.unlink(missing_ok=True)
    try:
        original_path.parent.rmdir()
    except OSError:
        pass


def test_handle_close_after_real_close_error_is_unknown_without_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, evidence, keys_parent = _setup(tmp_path)
    handle, _pubkey, _provenance = prepare_ephemeral_keypair(
        repo, evidence_root=evidence, keys_parent=keys_parent
    )
    real_close = os.close
    close_calls = 0

    def close_then_raise(fd: int) -> None:
        nonlocal close_calls
        if fd == handle._dir_fd:
            close_calls += 1
            real_close(fd)
            raise OSError("HANDLE_CLOSE_AFTER_REAL_CLOSE")
        real_close(fd)

    monkeypatch.setattr(os, "close", close_then_raise)

    observed = _capture_failure(handle.close)
    retry = _capture_failure(handle.close)

    assert isinstance(observed, OSError)
    assert getattr(handle, "_close_state", None) == "unknown"
    assert not handle._closed
    assert not handle._owns_dir_fd
    assert close_calls == 1
    assert isinstance(retry, RuntimeError)
    _assert_closed(handle._dir_fd)
    handle.path.unlink(missing_ok=True)
    try:
        handle.path.parent.rmdir()
    except OSError:
        pass
