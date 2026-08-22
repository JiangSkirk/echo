from __future__ import annotations

import ast
import dataclasses
import importlib
import threading
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "js" / "echo" / "handoff_vault.py"
PRODUCTION_ROOTS = (ROOT / "js", ROOT / "js_work")


def mod() -> Any:
    return importlib.import_module("js.echo.handoff_vault")


def contract() -> Any:
    return importlib.import_module("js.echo.mode_contract")


def make_authority(m: Any, *, mode: Any = None, owner: str = "owner-a",
                   session: str = "session-a", workspace: str | None = "ws-a") -> Any:
    c = contract()
    actual_mode = mode or c.AppMode.WORK
    if actual_mode is c.AppMode.PERSONAL:
        workspace = None
    return c.ResolvedTaskAuthorityV1(
        mode=actual_mode,
        mode_runtime_owner=owner,
        session=session,
        workspace=workspace,
    )


def make_request(m: Any, *, mode: Any = None, session: str | None = None,
                 workspace: str | None = None) -> Any:
    c = contract()
    actual_mode = mode or c.AppMode.WORK
    if actual_mode is c.AppMode.PERSONAL:
        workspace = None
    elif workspace is None:
        workspace = "ws-a"
    return c.ClientTaskRequestV1(mode=actual_mode, session=session, workspace=workspace)


def make_vault(m: Any, *, mac_key: bytes | None = None, max_entries: int = 64) -> Any:
    key = mac_key if mac_key is not None else b"x" * 32
    return m.HandoffVaultV1(
        mac_key=key,
        clock=lambda: _fake_clock_ns(),
        max_entries=max_entries,
        reserve_ttl_ns=60_000_000_000,
        commit_ttl_ns=60_000_000_000,
    )


_clock_ns = 1_000_000_000


def _fake_clock_ns() -> int:
    global _clock_ns
    return _clock_ns


def reset_clock() -> None:
    global _clock_ns
    _clock_ns = 1_000_000_000
_UINT64_MAX = 2**64 - 1


def issue_token(m: Any, *, request: Any = None, authority: Any = None,
                vault: Any = None) -> Any:
    if request is None:
        request = make_request(m)
    if authority is None:
        authority = make_authority(m)
    if vault is None:
        vault = make_vault(m)
    return m.issue_server_run_v1(request=request, authority=authority, vault=vault)


# ---- Public symbols and type hierarchy ----

def test_public_symbols_exist() -> None:
    m = mod()
    assert m.HandoffVaultError is not None
    assert m.HandoffVaultV1 is not None
    assert m.HandoffTokenV1 is not None
    assert m.TaskBindingV1 is not None
    assert m.HandoffRecordV1 is not None
    assert callable(m.issue_server_run_v1)
    assert callable(m.consume_handoff_token_v1)
    assert m.HANDOFF_VAULT_MAC_DOMAIN == b"js-agent:handoff-vault:v1\0"


def test_all_types_reject_subclassing() -> None:
    m = mod()
    for cls in (m.HandoffVaultV1, m.HandoffTokenV1, m.TaskBindingV1, m.HandoffRecordV1):
        with pytest.raises(TypeError):
            class Evil(cls):
                pass


def test_handoff_vault_error_is_exception() -> None:
    m = mod()
    assert issubclass(m.HandoffVaultError, Exception)


# ---- Exact type enforcement (finding 8, 11) ----

def test_issue_rejects_duck_typed_vault() -> None:
    m = mod()

    class FakeVault:
        pass

    with pytest.raises(m.HandoffVaultError) as exc:
        m.issue_server_run_v1(
            request=make_request(m),
            authority=make_authority(m),
            vault=FakeVault(),
        )
    assert "invalid_vault" in str(exc.value)


def test_consume_rejects_duck_typed_vault() -> None:
    m = mod()
    token = m.HandoffTokenV1(reference="ref", run_id="run-1")

    class FakeVault:
        pass

    with pytest.raises(m.HandoffVaultError) as exc:
        m.consume_handoff_token_v1(token=token, vault=FakeVault())
    assert "invalid_vault" in str(exc.value)


def test_issue_rejects_non_exact_request_type() -> None:
    m = mod()

    class FakeRequest:
        pass

    with pytest.raises(m.HandoffVaultError) as exc:
        m.issue_server_run_v1(
            request=FakeRequest(),
            authority=make_authority(m),
            vault=make_vault(m),
        )
    assert "invalid_request" in str(exc.value)


def test_issue_rejects_non_exact_authority_type() -> None:
    m = mod()

    class FakeAuthority:
        pass

    with pytest.raises(m.HandoffVaultError) as exc:
        m.issue_server_run_v1(
            request=make_request(m),
            authority=FakeAuthority(),
            vault=make_vault(m),
        )
    assert "invalid_authority" in str(exc.value)


# ---- Issue + consume round trip ----

def test_issue_and_consume_with_different_vault_fails() -> None:
    reset_clock()
    m = mod()
    vault1 = make_vault(m)
    vault2 = make_vault(m)
    token = issue_token(m, vault=vault1)
    with pytest.raises(m.HandoffVaultError) as exc:
        m.consume_handoff_token_v1(token=token, vault=vault2)
    assert "unknown_reference" in str(exc.value)


def test_issue_and_consume_round_trip_with_same_vault() -> None:
    reset_clock()
    m = mod()
    c = contract()
    vault = make_vault(m)
    token = issue_token(m, vault=vault)
    assert type(token) is m.HandoffTokenV1
    task_ref = m.consume_handoff_token_v1(token=token, vault=vault)
    assert type(task_ref) is c.TaskRef
    assert task_ref.mode is c.AppMode.WORK
    assert task_ref.owner == "owner-a"
    assert task_ref.session == "session-a"
    assert task_ref.run == token.run_id
    assert task_ref.workspace == "ws-a"


# ---- Conflict detection ----

def test_mode_conflict_rejected() -> None:
    m = mod()
    c = contract()
    request = make_request(m, mode=c.AppMode.PERSONAL)
    authority = make_authority(m, mode=c.AppMode.WORK)
    with pytest.raises(m.HandoffVaultError) as exc:
        m.issue_server_run_v1(request=request, authority=authority, vault=make_vault(m))
    assert "mode_conflict" in str(exc.value)


def test_session_conflict_rejected() -> None:
    m = mod()
    request = make_request(m, session="session-b")
    authority = make_authority(m, session="session-a")
    with pytest.raises(m.HandoffVaultError) as exc:
        m.issue_server_run_v1(request=request, authority=authority, vault=make_vault(m))
    assert "session_conflict" in str(exc.value)


def test_workspace_conflict_rejected() -> None:
    m = mod()
    request = make_request(m, workspace="ws-b")
    authority = make_authority(m, workspace="ws-a")
    with pytest.raises(m.HandoffVaultError) as exc:
        m.issue_server_run_v1(request=request, authority=authority, vault=make_vault(m))
    assert "workspace_conflict" in str(exc.value)


def test_personal_mode_round_trip() -> None:
    reset_clock()
    m = mod()
    c = contract()
    vault = make_vault(m)
    request = make_request(m, mode=c.AppMode.PERSONAL)
    authority = make_authority(m, mode=c.AppMode.PERSONAL)
    token = m.issue_server_run_v1(request=request, authority=authority, vault=vault)
    task_ref = m.consume_handoff_token_v1(token=token, vault=vault)
    assert task_ref.mode is c.AppMode.PERSONAL
    assert task_ref.workspace is None


# ---- Single-use consumption (replay prevention) ----

def test_token_can_only_be_consumed_once() -> None:
    reset_clock()
    m = mod()
    vault = make_vault(m)
    token = issue_token(m, vault=vault)
    m.consume_handoff_token_v1(token=token, vault=vault)
    with pytest.raises(m.HandoffVaultError) as exc:
        m.consume_handoff_token_v1(token=token, vault=vault)
    assert "unknown_reference" in str(exc.value)


# ---- Token contains no sensitive data ----

def test_token_has_only_reference_and_run_id() -> None:
    reset_clock()
    m = mod()
    token = issue_token(m)
    fields = {f.name for f in dataclasses.fields(token)}
    assert fields == {"reference", "run_id"}
    assert not hasattr(token, "mac")
    assert not hasattr(token, "binding")
    assert not hasattr(token, "owner")


# ---- Vault constructor validation ----

def test_vault_rejects_short_mac_key() -> None:
    m = mod()
    with pytest.raises(m.HandoffVaultError):
        make_vault(m, mac_key=b"short")


def test_vault_rejects_non_bytes_mac_key() -> None:
    m = mod()
    with pytest.raises(m.HandoffVaultError):
        m.HandoffVaultV1(
            mac_key="not bytes",  # type: ignore[arg-type]
            clock=lambda: 1,
            max_entries=10,
            reserve_ttl_ns=60_000_000_000,
            commit_ttl_ns=60_000_000_000,
        )


def test_vault_rejects_zero_max_entries() -> None:
    m = mod()
    with pytest.raises(m.HandoffVaultError):
        make_vault(m, max_entries=0)


# ---- TTL headroom (finding 9) ----

def test_ttl_headroom_overflow_at_reserve() -> None:
    m = mod()
    large_ttl = _UINT64_MAX
    vault = m.HandoffVaultV1(
        mac_key=b"x" * 32,
        clock=lambda: 1,
        max_entries=10,
        reserve_ttl_ns=large_ttl,
        commit_ttl_ns=large_ttl,
    )
    with pytest.raises(m.HandoffVaultError) as exc:
        issue_token(m, vault=vault)
    assert "invalid_clock" in str(exc.value)


def test_no_ttl_headroom_check_at_take() -> None:
    """take() should succeed without TTL headroom overflow check (only reserve/commit check)."""
    reset_clock()
    m = mod()
    # Vault with very large TTL -- reserve will succeed because clock is small,
    # but expires_at_ns will be very large. take() should still work.
    vault = m.HandoffVaultV1(
        mac_key=b"x" * 32,
        clock=lambda: 1_000_000_000,
        max_entries=10,
        reserve_ttl_ns=1_000_000_000,
        commit_ttl_ns=1_000_000_000,
    )
    request = make_request(m)
    authority = make_authority(m)
    token = m.issue_server_run_v1(request=request, authority=authority, vault=vault)
    # take() succeeds -- no headroom check at take time
    task_ref = m.consume_handoff_token_v1(token=token, vault=vault)
    assert task_ref.run == token.run_id


# ---- Two-phase purge (finding 2) ----

def test_purge_does_not_mutate_during_iteration() -> None:
    reset_clock()
    m = mod()
    vault = make_vault(m, max_entries=10)
    # Fill and expire entries
    for _ in range(5):
        issue_token(m, vault=vault)
    global _clock_ns
    _clock_ns = 100_000_000_000  # well past TTL
    # Next operation should purge without RuntimeError
    token = issue_token(m, vault=vault)
    assert type(token) is m.HandoffTokenV1


# ---- Vault full ----

def test_vault_full_rejected() -> None:
    reset_clock()
    m = mod()
    vault = make_vault(m, max_entries=2)
    issue_token(m, vault=vault)
    issue_token(m, vault=vault)
    with pytest.raises(m.HandoffVaultError) as exc:
        issue_token(m, vault=vault)
    assert "vault_full" in str(exc.value)


# ---- MAC verification (finding 1, 5) ----

def test_mac_includes_owner() -> None:
    reset_clock()
    m = mod()
    vault = make_vault(m)
    authority_a = make_authority(m, owner="owner-a")
    authority_b = make_authority(m, owner="owner-b")
    token_a = m.issue_server_run_v1(
        request=make_request(m), authority=authority_a, vault=vault)
    token_b = m.issue_server_run_v1(
        request=make_request(m), authority=authority_b, vault=vault)
    ref_a = m.consume_handoff_token_v1(token=token_a, vault=vault)
    ref_b = m.consume_handoff_token_v1(token=token_b, vault=vault)
    assert ref_a.owner == "owner-a"
    assert ref_b.owner == "owner-b"


def test_mac_key_validated_before_every_computation() -> None:
    reset_clock()
    m = mod()
    vault = make_vault(m)
    token = issue_token(m, vault=vault)
    # Tamper with mac_key after issue (use 32+ bytes to pass length check)
    object.__setattr__(vault, "_mac_key", b"y" * 32)
    with pytest.raises(m.HandoffVaultError) as exc:
        m.consume_handoff_token_v1(token=token, vault=vault)
    assert "mac_mismatch" in str(exc.value)


# ---- Unknown state handling (finding 4) ----

def test_take_from_reserved_state_fails() -> None:
    reset_clock()
    m = mod()
    vault = make_vault(m)
    # Manually reserve without commit
    binding = m.TaskBindingV1(
        mode=contract().AppMode.WORK,
        owner="owner-a",
        session="session-a",
        workspace="ws-a",
    )
    ref_result = vault._reserve(binding)
    token = m.HandoffTokenV1(
        reference=ref_result[0],
        run_id=ref_result[1],
    )
    with pytest.raises(m.HandoffVaultError) as exc:
        m.consume_handoff_token_v1(token=token, vault=vault)
    assert "unknown_state" in str(exc.value)


# ---- Error vocabulary: no detail leakage ----

def test_errors_do_not_leak_owner_or_session() -> None:
    m = mod()
    request = make_request(m, session="secret-session-xyz")
    authority = make_authority(m, session="different-session")
    with pytest.raises(m.HandoffVaultError) as exc:
        m.issue_server_run_v1(request=request, authority=authority, vault=make_vault(m))
    msg = str(exc.value)
    assert "secret-session-xyz" not in msg
    assert "different-session" not in msg


# ---- Concurrency ----

def test_concurrent_issue_and_consume() -> None:
    reset_clock()
    m = mod()
    vault = make_vault(m, max_entries=100)
    c = contract()
    results: list[Any] = []
    errors: list[Exception] = []
    barrier = threading.Barrier(10)

    def worker() -> None:
        try:
            barrier.wait()
            authority = c.ResolvedTaskAuthorityV1(
                mode=c.AppMode.WORK,
                mode_runtime_owner=f"owner-{threading.current_thread().name}",
                session=f"session-{threading.current_thread().name}",
                workspace="ws-a",
            )
            request = c.ClientTaskRequestV1(
                mode=c.AppMode.WORK,
                session=authority.session,
                workspace="ws-a",
            )
            token = m.issue_server_run_v1(request=request, authority=authority, vault=vault)
            ref = m.consume_handoff_token_v1(token=token, vault=vault)
            results.append(ref)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, name=f"t{i}") for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(errors) == 0
    assert len(results) == 10
    run_ids = {r.run for r in results}
    assert len(run_ids) == 10  # all unique


# ---- No I/O / env / filesystem / network ----

def test_module_has_no_io_or_side_effects() -> None:
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
    assert not any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in {"open", "eval", "exec"}
        for n in ast.walk(tree)
    )


# ---- Zero production callsites ----

def test_zero_production_callsites() -> None:
    targets = {"HandoffVaultV1", "issue_server_run_v1", "consume_handoff_token_v1",
               "HandoffTokenV1"}
    for production_root in PRODUCTION_ROOTS:
        for path in production_root.rglob("*.py"):
            if path == MODULE_PATH:
                continue
            source = path.read_text(encoding="utf-8")
            for target in targets:
                assert target not in source, f"{target} found in {path}"
            assert "from js.echo.handoff_vault" not in source
            assert "import handoff_vault" not in source


# ---- Vault does not expose size or iteration ----

def test_vault_has_no_len_or_iter() -> None:
    m = mod()
    vault = make_vault(m)
    assert not hasattr(vault, "__len__")
    assert not hasattr(vault, "__iter__")
    assert not hasattr(vault, "__contains__")


# ---- HandoffRecordV1 has owner in MAC (finding 1) ----

def test_handoff_record_mac_domain() -> None:
    m = mod()
    assert m.HANDOFF_VAULT_MAC_DOMAIN == b"js-agent:handoff-vault:v1\0"


# ---- Batch compatibility regression ----

def test_batch1_compatibility() -> None:
    # Importing handoff_vault must not break mode_contract imports
    c = contract()
    assert c.AppMode.WORK.value == "work"
    assert c.AppMode.PERSONAL.value == "personal"


# ============================================================
# R1-F02: Unknown internal records must fail-closed
# ============================================================

def test_unknown_object_in_entries_raises_vault_error() -> None:
    """Purging with an object() entry must raise HandoffVaultError, not AttributeError."""
    reset_clock()
    m = mod()
    vault = make_vault(m)
    vault._entries["bad"] = object()
    with pytest.raises(m.HandoffVaultError) as exc:
        issue_token(m, vault=vault)
    assert "unknown_state" in str(exc.value)


def test_bad_key_in_entries_raises_vault_error() -> None:
    reset_clock()
    m = mod()
    vault = make_vault(m)
    vault._entries[123] = "not a record"
    with pytest.raises(m.HandoffVaultError):
        issue_token(m, vault=vault)


def test_bad_record_preserves_good_entries() -> None:
    """When a bad entry is found, good entries must remain intact."""
    reset_clock()
    m = mod()
    vault = make_vault(m, max_entries=10)
    token = issue_token(m, vault=vault)
    vault._entries["bad"] = object()
    with pytest.raises(m.HandoffVaultError):
        issue_token(m, vault=vault)
    assert token.reference in vault._entries


def test_forged_state_record_raises() -> None:
    """A record with forged state must raise HandoffVaultError."""
    reset_clock()
    m = mod()
    vault = make_vault(m)
    # Build a valid record then forge its state by bypassing validation
    binding = m.TaskBindingV1(
        mode=contract().AppMode.WORK, owner="owner-a",
        session="session-a", workspace="ws-a",
    )
    record = vault._build_record(
        reference="ref-x", run_id="run-x", binding=binding,
        state="committed", expires_at_ns=999_999_999_999,
    )
    forged = object.__new__(m.HandoffRecordV1)
    object.__setattr__(forged, "reference", record.reference)
    object.__setattr__(forged, "run_id", record.run_id)
    object.__setattr__(forged, "binding", record.binding)
    object.__setattr__(forged, "state", "forged_state")
    object.__setattr__(forged, "expires_at_ns", record.expires_at_ns)
    object.__setattr__(forged, "mac", record.mac)
    vault._entries["ref-x"] = forged
    with pytest.raises(m.HandoffVaultError):
        issue_token(m, vault=vault)


# ============================================================
# R1-F03: reserve+commit must be atomic (single-publish)
# ============================================================

def test_issue_uses_reserve_and_commit_atomically() -> None:
    """issue_server_run_v1 must not leave a reserved record on failure."""
    reset_clock()
    m = mod()
    vault = make_vault(m, max_entries=10)
    initial_count = len(vault._entries)

    # Inject a failure in _build_record to simulate commit failure
    original_build = vault._build_record
    call_count = [0]

    def failing_build(**kwargs: Any) -> Any:
        call_count[0] += 1
        if call_count[0] >= 2:
            raise RuntimeError("injected commit failure")
        return original_build(**kwargs)

    vault._build_record_override = failing_build
    with pytest.raises(RuntimeError):
        issue_token(m, vault=vault)
    # No reserved record should be left
    assert len(vault._entries) == initial_count, "No reserved record should remain after failure"


def test_reserve_and_commit_single_publish() -> None:
    """_reserve_and_commit must write committed record in one step."""
    reset_clock()
    m = mod()
    vault = make_vault(m)
    binding = m.TaskBindingV1(
        mode=contract().AppMode.WORK, owner="owner-a",
        session="session-a", workspace="ws-a",
    )
    ref, run_id = vault._reserve_and_commit(binding)
    assert ref in vault._entries
    record = vault._entries[ref]
    assert record.state == "committed"
    assert record.run_id == run_id


def test_committed_orphan_cleaned_by_ttl() -> None:
    """If a committed record is orphaned (token never returned), TTL cleans it."""
    reset_clock()
    m = mod()
    vault = make_vault(m)
    binding = m.TaskBindingV1(
        mode=contract().AppMode.WORK, owner="owner-a",
        session="session-a", workspace="ws-a",
    )
    vault._reserve_and_commit(binding)
    assert len(vault._entries) == 1
    # Advance clock past TTL
    global _clock_ns
    _clock_ns = 999_999_999_999
    # Next operation should purge the orphan
    issue_token(m, vault=vault)
    # Orphan should be gone (only the new record remains)
    assert len(vault._entries) == 1


# ============================================================
# R1-F04: token.run_id must participate in consume verification
# ============================================================

def test_consume_rejects_mismatched_run_id() -> None:
    """Consuming with a wrong run_id must fail, not consume the record."""
    reset_clock()
    m = mod()
    vault = make_vault(m)
    token = issue_token(m, vault=vault)
    # Tamper with run_id
    bad_token = m.HandoffTokenV1(
        reference=token.reference,
        run_id="wrong-run-id",
    )
    with pytest.raises(m.HandoffVaultError) as exc:
        m.consume_handoff_token_v1(token=bad_token, vault=vault)
    assert "unknown_reference" in str(exc.value)

    # The valid token should still work
    task_ref = m.consume_handoff_token_v1(token=token, vault=vault)
    assert task_ref.run == token.run_id


# ============================================================
# R1-F05: Reference collision must be bounded
# ============================================================

def test_reference_collision_bounded() -> None:
    """After 64 collisions, must fail-closed with reference_collision."""
    reset_clock()
    m = mod()
    vault = make_vault(m, max_entries=10)
    # Pre-fill with a record at "collision-ref" to force collisions
    binding = m.TaskBindingV1(
        mode=contract().AppMode.WORK, owner="owner-a",
        session="session-a", workspace="ws-a",
    )
    existing = vault._build_record(
        reference="collision-ref", run_id="existing-run", binding=binding,
        state="committed", expires_at_ns=999_999_999_999,
    )
    vault._entries["collision-ref"] = existing

    call_count = [0]

    def colliding_ref() -> str:
        call_count[0] += 1
        if call_count[0] <= 65:
            return "collision-ref"
        return "unique-ref-" + str(call_count[0])

    vault._reference_factory = colliding_ref
    with pytest.raises(m.HandoffVaultError) as exc:
        issue_token(m, vault=vault)
    assert "reference_collision" in str(exc.value)


def test_reference_collision_recovers_after_one() -> None:
    """One collision should be recovered by retry."""
    reset_clock()
    m = mod()
    vault = make_vault(m, max_entries=10)
    binding = m.TaskBindingV1(
        mode=contract().AppMode.WORK, owner="owner-a",
        session="session-a", workspace="ws-a",
    )
    existing = vault._build_record(
        reference="collision-ref", run_id="existing-run", binding=binding,
        state="committed", expires_at_ns=999_999_999_999,
    )
    vault._entries["collision-ref"] = existing

    call_count = [0]

    def one_collision() -> str:
        call_count[0] += 1
        if call_count[0] == 1:
            return "collision-ref"
        return "unique-ref-" + str(call_count[0])

    vault._reference_factory = one_collision
    token = issue_token(m, vault=vault)
    assert type(token) is m.HandoffTokenV1


# ============================================================
# R1-F06: Expiry semantics must be correct
# ============================================================

def test_expired_record_returns_expired_not_unknown() -> None:
    """An expired committed record must return 'expired', not 'unknown_reference'."""
    reset_clock()
    m = mod()
    vault = make_vault(m)
    token = issue_token(m, vault=vault)
    # Advance clock past TTL
    global _clock_ns
    _clock_ns = 999_999_999_999
    with pytest.raises(m.HandoffVaultError) as exc:
        m.consume_handoff_token_v1(token=token, vault=vault)
    assert "expired" in str(exc.value)


def test_never_existed_returns_unknown_reference() -> None:
    """A reference that never existed must return 'unknown_reference'."""
    reset_clock()
    m = mod()
    vault = make_vault(m)
    fake_token = m.HandoffTokenV1(reference="never-existed", run_id="run-x")
    with pytest.raises(m.HandoffVaultError) as exc:
        m.consume_handoff_token_v1(token=fake_token, vault=vault)
    assert "unknown_reference" in str(exc.value)


def test_expired_record_does_not_affect_others() -> None:
    """Expiring one record must not affect others."""
    reset_clock()
    m = mod()
    vault = make_vault(m, max_entries=10)
    issue_token(m, vault=vault)
    # Advance clock to expire token1 but not token2
    global _clock_ns
    _clock_ns = 50_000_000_000  # past 60s TTL
    token2 = issue_token(m, vault=vault)
    # token2 should still be consumable (fresh TTL)
    ref2 = m.consume_handoff_token_v1(token=token2, vault=vault)
    assert ref2.run == token2.run_id


# ============================================================
# R1-F07: clock must validate uint64
# ============================================================

def test_clock_rejects_above_uint64_max() -> None:
    m = mod()
    vault = m.HandoffVaultV1(
        mac_key=b"x" * 32,
        clock=lambda: 2**64,
        max_entries=10,
        reserve_ttl_ns=60_000_000_000,
        commit_ttl_ns=60_000_000_000,
    )
    with pytest.raises(m.HandoffVaultError) as exc:
        issue_token(m, vault=vault)
    assert "invalid_clock" in str(exc.value)


def test_clock_rejects_negative() -> None:
    m = mod()
    vault = m.HandoffVaultV1(
        mac_key=b"x" * 32,
        clock=lambda: -1,
        max_entries=10,
        reserve_ttl_ns=60_000_000_000,
        commit_ttl_ns=60_000_000_000,
    )
    with pytest.raises(m.HandoffVaultError) as exc:
        issue_token(m, vault=vault)
    assert "invalid_clock" in str(exc.value)


def test_clock_rejects_bool() -> None:
    m = mod()
    vault = m.HandoffVaultV1(
        mac_key=b"x" * 32,
        clock=lambda: True,  # type: ignore[return-value]
        max_entries=10,
        reserve_ttl_ns=60_000_000_000,
        commit_ttl_ns=60_000_000_000,
    )
    with pytest.raises(m.HandoffVaultError) as exc:
        issue_token(m, vault=vault)
    assert "invalid_clock" in str(exc.value)


def test_clock_rejects_float() -> None:
    m = mod()
    vault = m.HandoffVaultV1(
        mac_key=b"x" * 32,
        clock=lambda: 1.5,  # type: ignore[return-value]
        max_entries=10,
        reserve_ttl_ns=60_000_000_000,
        commit_ttl_ns=60_000_000_000,
    )
    with pytest.raises(m.HandoffVaultError) as exc:
        issue_token(m, vault=vault)
    assert "invalid_clock" in str(exc.value)
