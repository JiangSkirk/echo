#!/usr/bin/env python3
"""Build a privacy-sanitized evidence export with layered MANIFEST + envelope."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from js.echo.ledger.evidence_export import (  # noqa: E402
    assert_docs_byte_identical,
    assert_no_self_hash_fields,
    build_sanitized_export,
    format_privacy_hits,
    privacy_scan,
    verify_manifest_v2,
)
from js.echo.ledger.release_gates import release_source_digest  # noqa: E402
from js.echo.ledger.strict_json import StrictJSONError, strict_load_path  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--source-digest", type=str, default="")
    parser.add_argument("--out-root", type=Path, default=None)
    parser.add_argument(
        "--top-level-doc",
        type=Path,
        action="append",
        default=[],
        help="Top-level docs to copy into sanitized-export/docs/",
    )
    args = parser.parse_args(argv)
    repo = args.repo_root.resolve()
    evidence = args.evidence_root.resolve()
    digest = args.source_digest or release_source_digest(repo)
    live = release_source_digest(repo)
    if digest != live:
        print(f"SOURCE_DIGEST_MISMATCH expected={digest} live={live}", file=sys.stderr)
        return 1

    docs = list(args.top_level_doc)
    if not docs:
        for name in (
            "JS_AGENT_FINAL_OPTIMIZATION_REPORT.md",
            "JS_AGENT_FINAL_EVIDENCE.json",
        ):
            path = repo / "docs" / name
            if path.is_file():
                docs.append(path)

    for doc in docs:
        if doc.suffix == ".json":
            try:
                payload = strict_load_path(doc)
            except StrictJSONError as exc:
                print(f"TOP_LEVEL_DOC_JSON_INVALID {doc.name}: {exc}", file=sys.stderr)
                return 1
            if not isinstance(payload, dict):
                print(f"TOP_LEVEL_DOC_NOT_OBJECT {doc.name}", file=sys.stderr)
                return 1
            assert_no_self_hash_fields(payload)

    try:
        result = build_sanitized_export(
            evidence_root=evidence,
            repo_root=repo,
            source_digest=digest,
            out_root=args.out_root or evidence,
            top_level_docs=docs,
        )
    except RuntimeError as exc:
        print(f"SANITIZED_EXPORT_FAILED {exc}", file=sys.stderr)
        return 1
    verify_manifest_v2(result.export_dir)
    hits = privacy_scan(result.export_dir)
    if hits:
        print(f"PRIVACY_SCAN_FAILED {format_privacy_hits(hits[:5])}", file=sys.stderr)
        return 1
    for doc in docs:
        export_copy = result.export_dir / "docs" / doc.name
        if export_copy.is_file():
            assert_docs_byte_identical(doc, export_copy)

    summary = {
        "ok": result.validation_ok,
        "export_dir": str(result.export_dir),
        "entry_count": result.entry_count,
        "total_bytes": result.total_bytes,
        "manifest_file_sha256": result.manifest_file_sha256,
        "envelope_file_sha256": result.envelope_file_sha256,
        "envelope_manifest_sha256": result.envelope_manifest_sha256,
        "source_digest": digest,
        "privacy_hits": 0,
        "passed_gates": list(result.passed_gates),
        "blockers": list(result.blockers),
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if result.validation_ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
