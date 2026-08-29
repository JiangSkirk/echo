from __future__ import annotations

# noqa: N806 (intentional UPPER_CASE constants in local scope)

# Sentinel owner used for pre-isolation / no-auth local sessions.  It is stored
# in the database as a non-NULL value so SQLite composite unique constraints
# reliably isolate rows.  It is treated as "local / legacy" and must never be
# used as a fallback for authenticated API-key owners.
_LEGACY_LOCAL_OWNER = "__legacy_local__"
_DEFAULT_MAX_SESSIONS_PER_OWNER = 1_000
_DEFAULT_MAX_SESSIONS_GLOBAL = 10_000
_DEFAULT_DREAM_LOG_RETENTION_DAYS = 90
_DEFAULT_MAX_DREAM_LOGS = 1_000
_DEFAULT_MAX_DREAM_LOGS_GLOBAL = 10_000
_DEFAULT_MAX_DREAM_DIARY_BYTES = 256 * 1024
_DEFAULT_PROPOSAL_RETENTION_DAYS = 90
_DEFAULT_MAX_PROPOSALS_PER_OWNER = 1_000
_DEFAULT_MAX_PROPOSALS_GLOBAL = 10_000
_TERMINAL_PROPOSAL_STATUSES: frozenset[str] = frozenset({"approved", "rejected", "auto_applied"})
