#!/usr/bin/env python3
"""Migrate an existing JS Agent memory DB to the hierarchical library (v2).

What it does (all idempotent):
  1. Ensures the new semantic columns exist (owner_key_hash / session_id /
     evidence) and the per-owner key-uniqueness index — by opening the store,
     whose ``_init_db`` performs the schema migration + the ``/user/family`` →
     ``/people/family`` remap and stamps PRAGMA user_version.
  2. Re-classifies still-unclassified rows (memory_path '' or '/general') using
     the keyword rules in ``_infer_entity_block`` so legacy facts land in the
     new taxonomy.

Legacy rows keep ``owner_key_hash = NULL`` (shared / visible to every owner),
so nothing is lost and the migration is safe to re-run.

Usage:
    uv run python scripts/migrate_memory_v2.py --state-dir ~/.js-agent
    uv run python scripts/migrate_memory_v2.py --state-dir ~/.js-agent --dry-run
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path
from typing import Any

# Make ``js`` importable when run directly from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_DB_NAME = "memory_enhanced.db"


def _connect_ro(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def analyze(db_path: Path) -> dict[str, Any]:
    """Read-only report of what the migration would touch."""
    report: dict[str, Any] = {
        "total": 0, "user_family": 0, "unclassified": 0, "by_block": {}
    }
    if not db_path.exists():
        report["error"] = f"{db_path} does not exist"
        return report
    with _connect_ro(db_path) as conn:
        cols = [c[1] for c in conn.execute("PRAGMA table_info(semantic_memories)")]
        report["has_owner_column"] = "owner_key_hash" in cols
        report["total"] = conn.execute("SELECT COUNT(*) FROM semantic_memories").fetchone()[0]
        if "memory_path" in cols:
            report["user_family"] = conn.execute(
                "SELECT COUNT(*) FROM semantic_memories "
                "WHERE memory_path = '/user/family' OR memory_path LIKE '/user/family/%'"
            ).fetchone()[0]
            report["unclassified"] = conn.execute(
                "SELECT COUNT(*) FROM semantic_memories "
                "WHERE memory_path IS NULL OR memory_path = '' OR memory_path = '/general'"
            ).fetchone()[0]
            for r in conn.execute(
                "SELECT memory_path, COUNT(*) c FROM semantic_memories "
                "GROUP BY memory_path ORDER BY c DESC"
            ):
                report["by_block"][r[0] or "(none)"] = r[1]
    return report


def migrate(state_dir: Path) -> dict[str, Any]:
    """Apply the migration in-place; returns a summary of changes."""
    from js.config import MemoryConfig
    from js.memory.enhanced_store import EnhancedMemoryStore

    db_path = state_dir / _DB_NAME
    before = analyze(db_path)

    # Instantiating the store runs _init_db: adds columns, drops legacy
    # UNIQUE(key), remaps /user/family → /people/family, bumps user_version.
    store = EnhancedMemoryStore(state_dir, MemoryConfig())
    reinferred = 0
    try:
        with sqlite3.connect(store.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, key, value, category, memory_path FROM semantic_memories "
                "WHERE memory_path IS NULL OR memory_path = '' OR memory_path = '/general'"
            ).fetchall()
            for r in rows:
                path, etype, ename, rel = store._infer_entity_block(
                    r["key"] or "", r["value"] or "", r["category"] or "fact"
                )
                if path and path != "/general" and path != (r["memory_path"] or ""):
                    conn.execute(
                        "UPDATE semantic_memories SET memory_path = ?, entity_type = ?, "
                        "entity_name = COALESCE(NULLIF(entity_name, ''), ?), "
                        "relation_type = COALESCE(NULLIF(relation_type, ''), ?) WHERE id = ?",
                        (path, etype, ename, rel, r["id"]),
                    )
                    reinferred += 1
            conn.commit()
    finally:
        store.close()

    after = analyze(db_path)
    return {"before": before, "after": after, "reinferred": reinferred}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Migrate JS Agent memory DB to v2 (hierarchical library).")
    parser.add_argument("--state-dir", required=True, type=Path, help="Agent state directory (contains memory_enhanced.db)")
    parser.add_argument("--dry-run", action="store_true", help="Report only; do not modify the database")
    args = parser.parse_args(argv)

    state_dir = args.state_dir.expanduser()
    db_path = state_dir / _DB_NAME

    if args.dry_run:
        report = analyze(db_path)
        print("=== DRY RUN (no changes written) ===")
        print(f"db: {db_path}")
        if report.get("error"):
            print(f"error: {report['error']}")
            return 1
        print(f"total memories      : {report['total']}")
        print(f"owner column present: {report.get('has_owner_column')}")
        print(f"/user/family rows   : {report['user_family']}  → will move to /people/family")
        print(f"unclassified rows   : {report['unclassified']}  → will attempt re-inference")
        print("blocks:")
        for path, count in report["by_block"].items():
            print(f"  {path}: {count}")
        return 0

    if not db_path.exists():
        print(f"error: {db_path} does not exist", file=sys.stderr)
        return 1

    result = migrate(state_dir)
    print("=== MIGRATION COMPLETE ===")
    print(f"db: {db_path}")
    print(f"/user/family before  : {result['before']['user_family']}  (remapped to /people/family)")
    print(f"re-inferred rows     : {result['reinferred']}")
    print(f"unclassified before  : {result['before']['unclassified']}")
    print(f"unclassified after   : {result['after']['unclassified']}")
    print("blocks after:")
    for path, count in result["after"]["by_block"].items():
        print(f"  {path}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
