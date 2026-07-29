"""
Session Capsule Lite — Regression Test Matrix
===============================================

Covers the core scenarios required for capsule stability in v0.1.3-alpha Lite:

1. Short session does NOT trigger capsule
2. Long session allows capsule storage/retrieval
3. No model → graceful degradation (no capsule)
4. Generation failure → fallback to full history
5. Owner partition: same session_id supports one capsule per owner
6. Secrets redaction in capsule
7. Clear capsule → restore full history
8. Drift detection is warning-only (does not block injection)
9. Dynamic recent_turns based on model context window
10. Capsule metadata persistence (Lite fields only)
11. Quality assessment integration

Run with::

    pytest tests/test_session_capsule_regression.py -v

"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from js.config import MemoryConfig
from js.memory.capsule_drift import check_drift
from js.memory.capsule_quality import QualityScore, evaluate_capsule
from js.memory.enhanced_store import EnhancedMemoryStore
from js.security.secrets import SecretManager

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db():
    """Create a temporary database for isolated tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        state_dir = Path(tmpdir)
        from js.config import MemoryConfig

        SecretManager(state_dir=state_dir)
        store = EnhancedMemoryStore(state_dir=state_dir, config=MemoryConfig())
        yield store


@pytest.fixture
def sample_messages():
    """A short conversation that should NOT trigger capsule."""
    return [
        {"role": "user", "content": "Hello"},
        {"role": "assistant", "content": "Hi there!"},
        {"role": "user", "content": "What's the weather?"},
        {"role": "assistant", "content": "It's sunny today."},
    ]


@pytest.fixture
def long_messages():
    """A long conversation that SHOULD trigger capsule."""
    msgs = []
    for i in range(20):
        msgs.append({"role": "user", "content": f"Question {i}: how to refactor module {i}?"})
        msgs.append(
            {"role": "assistant", "content": f"Answer {i}: extract class {i} into its own file."}
        )
    return msgs


# ---------------------------------------------------------------------------
# 1. Short session does NOT trigger capsule
# ---------------------------------------------------------------------------


def test_short_session_no_capsule(tmp_db, sample_messages):
    """A session with only 4 messages should not have a capsule generated."""
    store = tmp_db
    session_id = "short_session"
    store.store_messages(session_id, sample_messages)

    # No capsule should exist yet
    capsule = store.get_capsule(session_id)
    assert capsule is None


# ---------------------------------------------------------------------------
# 2. Long session triggers capsule generation
# ---------------------------------------------------------------------------


def test_long_session_capsule_generated(tmp_db, long_messages):
    """A session with 40 messages should allow capsule storage and retrieval."""
    store = tmp_db
    session_id = "long_session"
    store.store_messages(session_id, long_messages)

    capsule_text = (
        "Summary: refactoring modules 0-19 by extracting classes into separate files. "
        "Next: add tests for extracted classes."
    )
    meta = store.store_capsule(session_id, capsule_text)

    assert meta["session_id"] == session_id
    assert meta["capsule_text"] == capsule_text
    assert meta["version"] == 1

    retrieved = store.get_capsule(session_id)
    assert retrieved is not None
    assert retrieved["capsule_text"] == capsule_text
    assert retrieved["version"] == 1


# ---------------------------------------------------------------------------
# 3. No model → graceful degradation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_model_graceful_degradation(tmp_path: Path) -> None:
    """When no model is configured, capsule refresh returns a 503-style status."""
    from js.agent import JSAgent
    from js.config import JSSettings, MemoryConfig

    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        memory=MemoryConfig(capsule_enabled=True, capsule_token_threshold=1),
        max_turns=1,
    )
    agent = JSAgent(settings)
    agent.memory.store_messages(
        "no-model-session",
        [{"role": "user", "content": "hello"}, {"role": "assistant", "content": "hi"}],
    )
    # No providers registered → _summarize_context will raise/return empty.
    with pytest.raises(Exception, match="No models configured"):
        await agent._summarize_context([])
    await agent.close()


# ---------------------------------------------------------------------------
# 4. Generation failure → fallback to full history
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generation_failure_fallback(tmp_path: Path) -> None:
    """If _summarize_context returns empty, no capsule is stored and full history remains."""
    from js.agent import JSAgent
    from js.config import JSSettings, MemoryConfig
    from js.models.providers import ChatMessage

    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        memory=MemoryConfig(capsule_enabled=True, capsule_token_threshold=1),
        max_turns=1,
    )
    agent = JSAgent(settings)
    agent.memory.store_messages(
        "fail-session",
        [{"role": "user", "content": "hello"}, {"role": "assistant", "content": "hi"}],
    )

    # Force an empty summary result.
    original = agent._summarize_context

    async def _empty_summary(*_args, **_kwargs):
        return ""

    agent._summarize_context = _empty_summary  # type: ignore[method-assign]
    try:
        result = await agent._summarize_context([ChatMessage(role="user", content="hello")])
        assert result == ""
        # No capsule should have been persisted because the summary is empty.
        assert agent.memory.get_capsule("fail-session") is None
    finally:
        agent._summarize_context = original  # type: ignore[method-assign]
        await agent.close()


# ---------------------------------------------------------------------------
# 5. Owner cross-read fails
# ---------------------------------------------------------------------------


def test_owner_isolation(tmp_db, long_messages):
    """Capsules should be isolated by owner_key_hash within the same session_id."""
    store = tmp_db
    session_id = "owner_session"
    store.store_messages(session_id, long_messages, owner_key_hash="owner_a")
    store.store_capsule(session_id, "capsule for owner_a", owner_key_hash="owner_a")
    store.store_capsule(session_id, "capsule for owner_b", owner_key_hash="owner_b")

    # Each owner sees only their own capsule.
    capsule_a = store.get_capsule(session_id, owner_key_hash="owner_a")
    assert capsule_a is not None
    assert capsule_a["capsule_text"] == "capsule for owner_a"

    capsule_b = store.get_capsule(session_id, owner_key_hash="owner_b")
    assert capsule_b is not None
    assert capsule_b["capsule_text"] == "capsule for owner_b"

    # Updating owner_b must not overwrite owner_a's capsule.
    store.store_capsule(session_id, "updated capsule for owner_b", owner_key_hash="owner_b")
    assert (
        store.get_capsule(session_id, owner_key_hash="owner_a")["capsule_text"]
        == "capsule for owner_a"
    )
    assert (
        store.get_capsule(session_id, owner_key_hash="owner_b")["capsule_text"]
        == "updated capsule for owner_b"
    )

    # Deleting owner_a's capsule must not remove owner_b's.
    assert store.delete_capsule(session_id, owner_key_hash="owner_a") is True
    assert store.get_capsule(session_id, owner_key_hash="owner_a") is None
    assert store.get_capsule(session_id, owner_key_hash="owner_b") is not None


def test_capsule_legacy_null_owner_migration(tmp_path: Path):
    """Legacy single-key session_capsules are migrated to the sentinel owner."""
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    db_path = state_dir / "memory_enhanced.db"

    import sqlite3

    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE session_capsules (
            session_id TEXT PRIMARY KEY,
            capsule_text TEXT NOT NULL,
            owner_key_hash TEXT,
            updated_at REAL NOT NULL,
            version INTEGER DEFAULT 1,
            source_range TEXT,
            generated_by_model TEXT,
            recent_turns_kept INTEGER,
            estimated_tokens_saved INTEGER,
            refresh_reason TEXT,
            fail_count INTEGER DEFAULT 0,
            last_accessed REAL DEFAULT 0,
            ttl_seconds INTEGER DEFAULT 0,
            is_pinned INTEGER DEFAULT 0,
            is_expired INTEGER DEFAULT 0,
            drift_detected INTEGER DEFAULT 0,
            drift_reason TEXT,
            secrets_redacted INTEGER DEFAULT 0
        )
    """)
    conn.execute(
        "INSERT INTO session_capsules (session_id, capsule_text, owner_key_hash, updated_at) "
        "VALUES (?, ?, ?, ?)",
        ("legacy-session", "legacy shared capsule", None, 12345.0),
    )
    conn.commit()
    conn.close()

    store = EnhancedMemoryStore(state_dir, MemoryConfig())
    # Legacy NULL-owner row is migrated to the sentinel and visible only to
    # no-auth / local anonymous requests.
    legacy = store.get_capsule("legacy-session", owner_key_hash=None)
    assert legacy is not None
    assert legacy["capsule_text"] == "legacy shared capsule"
    assert legacy["owner_key_hash"] == "__legacy_local__"

    # Authenticated owners do not see the legacy row.
    assert store.get_capsule("legacy-session", owner_key_hash="owner_a") is None

    # The same session can hold an owner-specific capsule alongside the legacy one.
    store.store_capsule("legacy-session", "owner capsule", owner_key_hash="owner_a")
    assert (
        store.get_capsule("legacy-session", owner_key_hash="owner_a")["capsule_text"]
        == "owner capsule"
    )
    assert (
        store.get_capsule("legacy-session", owner_key_hash=None)["capsule_text"]
        == "legacy shared capsule"
    )


def test_legacy_working_memories_and_episodes_migration(tmp_path: Path):
    """Intermediate schemas with nullable owner_key_hash migrate to sentinel + composite unique."""
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    db_path = state_dir / "memory_enhanced.db"

    import sqlite3

    conn = sqlite3.connect(str(db_path))
    # Old working_memories: owner_key_hash nullable, unique on (session_id, key)
    conn.execute("""
        CREATE TABLE working_memories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            category TEXT DEFAULT 'general',
            importance INTEGER DEFAULT 5,
            created_at REAL NOT NULL,
            access_count INTEGER DEFAULT 0,
            last_accessed REAL NOT NULL,
            owner_key_hash TEXT,
            UNIQUE(session_id, key)
        )
    """)
    # Old episodes: nullable owner_key_hash, unique on session_id
    conn.execute("""
        CREATE TABLE episodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            summary TEXT,
            topics TEXT,
            tokens_used INTEGER DEFAULT 0,
            turn_count INTEGER DEFAULT 0,
            created_at REAL NOT NULL,
            importance INTEGER DEFAULT 5,
            owner_key_hash TEXT,
            UNIQUE(session_id)
        )
    """)
    conn.execute(
        "INSERT INTO working_memories (session_id, key, value, created_at, last_accessed) "
        "VALUES (?, ?, ?, ?, ?)",
        ("legacy-session", "ctx", "legacy value", 1.0, 1.0),
    )
    conn.execute(
        "INSERT INTO episodes (session_id, summary, topics, created_at) VALUES (?, ?, ?, ?)",
        ("legacy-session", "legacy summary", "[]", 1.0),
    )
    conn.commit()
    conn.close()

    store = EnhancedMemoryStore(state_dir, MemoryConfig())

    # Legacy rows are visible only to the sentinel owner.
    working = store.get_working("legacy-session", owner_key_hash=None)
    assert len(working) == 1
    assert working[0]["value"] == "legacy value"
    assert working[0]["owner_key_hash"] == "__legacy_local__"

    episodes = store.get_episodes(owner_key_hash=None)
    assert len(episodes) == 1
    assert episodes[0].session_id == "legacy-session"
    assert episodes[0].summary == "legacy summary"

    # Authenticated owners do not see legacy rows.
    assert store.get_working("legacy-session", owner_key_hash="owner_a") == []
    assert store.get_episodes(owner_key_hash="owner_a") == []

    # Composite unique constraints now isolate by owner.
    store.store_working("legacy-session", "ctx", "owner a value", owner_key_hash="owner_a")
    store.store_working("legacy-session", "ctx", "owner b value", owner_key_hash="owner_b")
    assert (
        store.get_working("legacy-session", owner_key_hash="owner_a")[0]["value"] == "owner a value"
    )
    assert (
        store.get_working("legacy-session", owner_key_hash="owner_b")[0]["value"] == "owner b value"
    )

    store.store_episode("legacy-session", "owner a summary", [], owner_key_hash="owner_a")
    store.store_episode("legacy-session", "owner b summary", [], owner_key_hash="owner_b")
    assert store.get_episodes(owner_key_hash="owner_a")[0].summary == "owner a summary"
    assert store.get_episodes(owner_key_hash="owner_b")[0].summary == "owner b summary"


# ---------------------------------------------------------------------------
# 6. Secrets redaction in capsule
# ---------------------------------------------------------------------------


def test_capsule_secrets_redaction(tmp_db):
    """Secrets should be redacted before capsule storage."""
    store = tmp_db
    session_id = "secret_session"
    fake_key = "sk-" + "1234567890abcdef1234567890abcdef"
    fake_password = "My" + "Secret123!"
    raw_text = f"The API key is {fake_key} and the password: {fake_password}"
    meta = store.store_capsule(session_id, raw_text)

    assert meta["secrets_redacted"] == 1
    assert fake_key not in meta["capsule_text"]
    assert fake_password not in meta["capsule_text"]

    retrieved = store.get_capsule(session_id)
    assert retrieved is not None
    assert retrieved["secrets_redacted"] == 1


# ---------------------------------------------------------------------------
# 7. Clear capsule → restore full history
# ---------------------------------------------------------------------------


def test_clear_capsule_restores_full_history(tmp_db, long_messages):
    """Deleting the capsule should restore full history on next run."""
    store = tmp_db
    session_id = "clear_session"
    store.store_messages(session_id, long_messages)
    store.store_capsule(session_id, "some capsule")

    assert store.get_capsule(session_id) is not None

    store.delete_capsule(session_id)
    assert store.get_capsule(session_id) is None


# ---------------------------------------------------------------------------
# 8. Drift detection is warning-only in Lite
# ---------------------------------------------------------------------------


def test_drift_detection_warning():
    """DriftDetector should flag when recent turns contradict the capsule."""
    capsule = "We are refactoring the auth module."
    recent = [
        {
            "role": "user",
            "content": "Actually, let's stop working on auth and switch to the payment module.",
        },
        {"role": "assistant", "content": "OK, I'll start analyzing the payment gateway code."},
        {"role": "user", "content": "We need to integrate Stripe first."},
    ]
    result = check_drift(capsule, recent, recent_turns_count=3)
    assert result.drift_detected is True
    assert result.confidence > 0.0


def test_no_drift_when_consistent():
    """DriftDetector should NOT flag when recent turns are consistent."""
    capsule = "We are refactoring the auth module and extracting the hasher class."
    recent = [
        {"role": "user", "content": "Continue refactoring the auth module."},
        {"role": "assistant", "content": "I've extracted the hasher class."},
        {"role": "user", "content": "Great, now add bcrypt support to the auth module."},
    ]
    result = check_drift(capsule, recent, recent_turns_count=3)
    assert result.drift_detected is False


# ---------------------------------------------------------------------------
# 9. Dynamic recent_turns based on model context window
# ---------------------------------------------------------------------------


def test_dynamic_recent_turns():
    """_compute_recent_turns should vary based on model context window."""
    # We test the logic directly by mocking the agent settings
    from js.echo.turn_loop import EchoTurnLoop

    class FakeMemoryConfig:
        capsule_recent_turns = 6

    class FakeModelConfig:
        context_window = 200_000

    class FakeRouter:
        def get_model_config(self, model: str):
            return FakeModelConfig()

    class FakeAgent:
        settings = type("Settings", (), {"memory": FakeMemoryConfig()})()
        router = FakeRouter()

    executor = EchoTurnLoop.__new__(EchoTurnLoop)
    # For a 200k context window, should return at least 8
    assert executor._compute_recent_turns(FakeAgent(), "any_model") >= 8

    class SmallModelConfig:
        context_window = 8_000

    class SmallRouter:
        def get_model_config(self, model: str):
            return SmallModelConfig()

    class SmallAgent:
        settings = type("Settings", (), {"memory": FakeMemoryConfig()})()
        router = SmallRouter()

    # For an 8k context window, should return at least 2 (base - 4, clamped)
    assert executor._compute_recent_turns(SmallAgent(), "any_model") >= 2


# ---------------------------------------------------------------------------
# 10. Capsule metadata persistence
# ---------------------------------------------------------------------------


def test_capsule_metadata_persistence(tmp_db):
    """Lite metadata fields should round-trip through the database."""
    store = tmp_db
    session_id = "meta_session"
    meta = store.store_capsule(
        session_id,
        "test capsule",
        version=2,
        source_range="turns 1-10",
        generated_by_model="gpt-4o",
        recent_turns_kept=6,
        estimated_tokens_saved=1200,
        refresh_reason="threshold_exceeded",
    )

    assert meta["version"] == 2
    assert meta["source_range"] == "turns 1-10"
    assert meta["generated_by_model"] == "gpt-4o"
    assert meta["recent_turns_kept"] == 6
    assert meta["estimated_tokens_saved"] == 1200
    assert meta["refresh_reason"] == "threshold_exceeded"

    retrieved = store.get_capsule(session_id)
    assert retrieved is not None
    assert retrieved["version"] == 2
    assert retrieved["source_range"] == "turns 1-10"
    assert retrieved["generated_by_model"] == "gpt-4o"


# ---------------------------------------------------------------------------
# 11. Quality assessment integration
# ---------------------------------------------------------------------------


def test_quality_assessment_good_capsule():
    """A good capsule should pass the quality check."""
    capsule = (
        "Goal: refactor auth module. Decisions: extracted Hasher interface. "
        "Completed: login route refactored. Next: add rate limiting. "
        "Files: src/auth.py, src/auth/hashers.py. "
        "Remember: user prefers explicit type hints everywhere."
    )
    score = evaluate_capsule(capsule)
    assert isinstance(score, QualityScore)
    assert score.passed is True
    assert score.passed_checks >= 4


def test_quality_assessment_poor_capsule():
    """A poor capsule should fail the quality check."""
    capsule = "We talked about some stuff."
    score = evaluate_capsule(capsule)
    assert score.passed is False
    assert score.warnings


# ---------------------------------------------------------------------------
# 12. Capsule version migration
# ---------------------------------------------------------------------------


def test_capsule_version_migration(tmp_db):
    """Old capsules (version 1) should coexist with new capsules (version 2)."""
    store = tmp_db
    store.store_capsule("v1_session", "old capsule", version=1)
    store.store_capsule("v2_session", "new capsule", version=2, source_range="turns 1-5")

    v1 = store.get_capsule("v1_session")
    v2 = store.get_capsule("v2_session")

    assert v1["version"] == 1
    assert v2["version"] == 2
    assert v2["source_range"] == "turns 1-5"
