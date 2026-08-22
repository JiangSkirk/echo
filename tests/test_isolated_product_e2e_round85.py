from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
import sys
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from openpyxl import Workbook

from js.echo.attachment_gate import owner_slug, session_slug
from js.echo.ledger.journal import EchoJournal
from js.echo.ledger.release_gates import (
    _ISOLATED_VENV_E2E_REQUIRED_STEPS,
    _ISOLATED_VENV_E2E_SCHEMA_VERSION,
    _ISOLATED_VENV_E2E_SERVER_STEP,
    _valid_isolated_venv_e2e,
    _verify_work_ledger_receipt_binding,
    _work_ledger_chain_record_dict,
    build_work_ledger_receipt_binding,
    release_source_digest,
)
from js.echo.ledger.service import _scope_partition_slugs


def _build_fixture_ledger_chain(
    *,
    owner: str = "iso-e2e-owner",
    run_id: str = "iso-e2e-work-run",
    tool_name: str = "excel_write",
    lease_id: str = "a" * 32,
    effect_id: str = "effect-iso-e2e-work",
    journal_path: Path | None = None,
    mac_key: bytes = b"\x01" * 32,
    output_hash: str = "c" * 64,
) -> tuple[list[dict[str, object]], int, str]:
    journal = EchoJournal(mac_key=mac_key)
    journal.append(
        record_type="intake",
        tenant_id=owner,
        run_id=run_id,
        payload={"payload_ref": "preface"},
    )
    journal.append(
        record_type="decision",
        tenant_id=owner,
        run_id=run_id,
        payload={"decision_id": "decision-iso-e2e"},
    )
    journal.append(
        record_type="policy_decision",
        tenant_id=owner,
        run_id=run_id,
        payload={"policy_decision_id": "policy-iso-e2e"},
    )
    args_hash = "b" * 64
    tool_effect = {
        "product_id": "js-work",
        "session_id": "iso-e2e-work",
        "tool_name": tool_name,
        "lease_id": lease_id,
        "args_hash": args_hash,
    }
    seal = {
        "seal_id": "seal-iso-e2e",
        "effect_id": effect_id,
        "tenant_id": owner,
        "action_kind": "tool",
    }
    journal.append(
        record_type="permit",
        tenant_id=owner,
        run_id=run_id,
        payload={
            "effect_id": effect_id,
            "tool_effect": tool_effect,
            "seal_id": "seal-iso-e2e",
            "seal": seal,
        },
    )
    journal.append(
        record_type="outbox",
        tenant_id=owner,
        run_id=run_id,
        payload={
            "effect_id": effect_id,
            "outbox_id": "outbox-iso-e2e",
            "sealed_input_ref": args_hash,
            "seal": seal,
        },
    )
    journal.append(
        record_type="outbox_claimed",
        tenant_id=owner,
        run_id=run_id,
        payload={"effect_id": effect_id, "outbox_id": "outbox-iso-e2e"},
    )
    journal.append(
        record_type="receipt",
        tenant_id=owner,
        run_id=run_id,
        payload={
            "effect_id": effect_id,
            "outbox_id": "outbox-iso-e2e",
            "status": "ok",
            "output_hash": output_hash,
        },
    )
    merge = journal.append(
        record_type="merge",
        tenant_id=owner,
        run_id=run_id,
        payload={"effect_id": effect_id, "status": "ok"},
    )
    if journal_path is not None:
        from js.echo.ledger.journal import _record_to_json

        journal_path.parent.mkdir(parents=True, exist_ok=True)
        journal_path.write_text(
            "".join(_record_to_json(record) + "\n" for record in journal.records),
            encoding="utf-8",
        )
    chain = journal.records[-5:]
    return (
        [_work_ledger_chain_record_dict(record) for record in chain],
        merge.seq,
        merge.record_hash,
    )


def _work_receipt_with_ledger_binding(
    *,
    output_sha256: str,
    ledger_chain: list[dict[str, object]],
    ledger_sequence: int,
    record_hash: str,
    lease_id: str = "a" * 32,
    effect_id: str = "effect-iso-e2e-work",
    evidence_kind: str | None = None,
    journal_sha256: str = "d" * 64,
    mac_key_sha256: str = "e" * 64,
) -> dict[str, object]:
    receipt: dict[str, object] = {
        "product_id": "js-work",
        "owner": "iso-e2e-owner",
        "session": "iso-e2e-work",
        "run_id": "iso-e2e-work-run",
        "tool_name": "excel_write",
        "lease_id": lease_id,
        "effect_id": effect_id,
        "lease_consumed": True,
        "journal_records_added": True,
        "terminal": True,
        "status": "ok",
        "terminal_status": "ok",
        "output_exists": True,
        "output_sha256": output_sha256,
        "output_cells": [["iso", "e2e", "leased"]],
        "output_path": (
            f"owners/{owner_slug('iso-e2e-owner')}/"
            f"{session_slug('iso-e2e-work')}/outputs/iso-e2e.xlsx"
        ),
        "journal_relative_path": "echo/ledger/partitions/{}/{}/{}/chat.jsonl".format(
            *_scope_partition_slugs(
                tenant_id="iso-e2e-owner",
                product_id="js-work",
                session_id="iso-e2e-work",
            )
        ),
        "journal_sha256": journal_sha256,
        "ledger_sequence": ledger_sequence,
        "record_hash": record_hash,
        "ledger_chain": ledger_chain,
    }
    if evidence_kind is not None:
        signature_payload = {
            "journal_sha256": journal_sha256,
            "arguments_sha256": "b" * 64,
            "output_sha256": output_sha256,
            "product_id": "js-work",
            "owner": "iso-e2e-owner",
            "session": "iso-e2e-work",
            "run_id": "iso-e2e-work-run",
            "effect_id": effect_id,
        }
        private_key = Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(b"js-agent-test-fixture-e2e-ledger-key-v1").digest()
        )
        public_raw = private_key.public_key().public_bytes_raw()
        receipt.update(
            {
                "journal_evidence_path": f"e2e/work/{evidence_kind}/ledger.journal",
                "arguments_sha256": "b" * 64,
                "ledger_signature_b64": base64.b64encode(
                    private_key.sign(
                        json.dumps(
                            signature_payload, sort_keys=True, separators=(",", ":")
                        ).encode()
                    )
                ).decode(),
                "pubkey_fingerprint": hashlib.sha256(public_raw).hexdigest(),
            }
        )
    return receipt


def _write_xlsx(path: Path, cells: list[list[str]]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    workbook = Workbook()
    sheet = workbook.active
    for row_index, row in enumerate(cells, start=1):
        for col_index, value in enumerate(row, start=1):
            sheet.cell(row=row_index, column=col_index, value=value)
    buffer = BytesIO()
    workbook.save(buffer)
    payload = buffer.getvalue()
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _write_artifact(path: Path, payload: bytes) -> dict[str, object]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return {
        "path": path.name
        if path.parent.name == "artifacts"
        else str(path.relative_to(path.parents[2])),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
    }


def _server_detail(
    *,
    output_sha256: str,
    ledger_chain: list[dict[str, object]],
    ledger_sequence: int,
    record_hash: str,
    evidence_kind: str | None = None,
    journal_sha256: str = "d" * 64,
    mac_key_sha256: str = "e" * 64,
    **overrides: object,
) -> dict[str, object]:
    detail: dict[str, object] = {
        "chat_status": 200,
        "provider_calls": 3,
        "provider_scenarios": {"chat": 1, "attachment": 1, "tool": 1},
        "attachment_consumed": True,
        "attachment_marker_in_messages": True,
        "unexpected_provider_calls": [],
        "all_provider_hosts_loopback": True,
        "ws_terminal_ok": True,
        "ws_saw_token": True,
        "ws_saw_thinking": True,
        "ws_saw_tool_call": True,
        "ws_saw_done": True,
        "work_receipt": _work_receipt_with_ledger_binding(
            output_sha256=output_sha256,
            ledger_chain=ledger_chain,
            ledger_sequence=ledger_sequence,
            record_hash=record_hash,
            evidence_kind=evidence_kind,
            journal_sha256=journal_sha256,
            mac_key_sha256=mac_key_sha256,
        ),
    }
    detail.update(overrides)
    return detail


def _step_record(
    name: str,
    *,
    source_digest: str,
    root: Path,
    evidence_dir: Path,
    detail: dict[str, object] | None = None,
) -> dict[str, object]:
    started = datetime(2026, 7, 23, 0, 0, 0, tzinfo=UTC)
    finished = started + timedelta(seconds=1)
    if name.startswith("build:"):
        cwd = root.resolve()
        build_python = root / ".venv" / "bin" / "python"
        build_python.parent.mkdir(parents=True, exist_ok=True)
        if not build_python.exists():
            shutil.copy2(sys.executable, build_python)
        argv = [
            str(build_python.resolve()),
            "-m",
            "build",
            "--outdir",
            str((evidence_dir / "e2e" / "artifacts").resolve()),
            "--no-isolation",
        ]
    else:
        kind = "wheel" if name.startswith("wheel:") else "sdist"
        cwd = (evidence_dir / "e2e" / "runtime" / f"install-{kind}").resolve()
        cwd.mkdir(parents=True, exist_ok=True)
        venv = cwd / "venv"
        (venv / "bin").mkdir(parents=True, exist_ok=True)
        if not (venv / "bin" / "python").exists():
            shutil.copy2(sys.executable, venv / "bin" / "python")
        python = str(venv / "bin" / "python")
        (evidence_dir / "wheelhouse").mkdir(parents=True, exist_ok=True)
        suffix = name.removeprefix(f"{kind}: ")
        if suffix == "create venv":
            argv = [str((root / ".venv" / "bin" / "python").resolve()), "-m", "venv", str(venv)]
        elif suffix == "pip install build backends offline":
            argv = [
                python,
                "-m",
                "pip",
                "install",
                "--no-index",
                "--find-links",
                str((evidence_dir / "wheelhouse").resolve()),
                "--no-input",
                "hatchling",
                "pathspec",
                "packaging",
                "trove-classifiers",
                "pluggy",
            ]
        elif suffix == "pip install artifact offline (echo-tokenizer,office)":
            artifact = (
                evidence_dir
                / "e2e"
                / "artifacts"
                / ("js_agent-0.whl" if kind == "wheel" else "js_agent-0.tar.gz")
            )
            argv = [
                python,
                "-m",
                "pip",
                "install",
                "--no-index",
                "--find-links",
                str((evidence_dir / "wheelhouse").resolve()),
                "--no-input",
            ]
            report = evidence_dir / "e2e" / "pip" / f"{kind}.install-report.json"
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(
                json.dumps(
                    {
                        "install": [
                            {
                                "metadata": {"name": "js-agent", "version": "0"},
                                "download_info": {"archive_info": {"hash": "sha256=" + "a" * 64}},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            argv.extend(["--report", str(report.resolve())])
            if kind == "sdist":
                argv.append("--no-build-isolation")
            argv.append(f"{artifact}[echo-tokenizer,office]")
        elif suffix == "pip check":
            argv = [python, "-m", "pip", "check"]
        elif suffix == "import js/js_work from venv site-packages":
            argv = [python, "-c", "import js, js_work\nassert 'site-packages'"]
        elif suffix == "tokenizer loads offline from vendored cache":
            argv = [python, "-c", "from js.echo.context_tokenizer import tiktoken_counter_factory"]
        elif suffix == "CLI js --help":
            argv = [str(venv / "bin" / "js"), "--help"]
        elif suffix == "CLI js work --help":
            argv = [str(venv / "bin" / "js"), "work", "--help"]
        elif suffix == "CLI js-work --help":
            argv = [str(venv / "bin" / "js-work"), "--help"]
        elif suffix == "CLI python -m js_work --help":
            argv = [python, "-m", "js_work", "--help"]
        else:
            argv = [python, str(cwd / "server_e2e.py")]
    import_evidence: dict[str, object] | None = None
    if name.endswith("import js/js_work from venv site-packages"):
        purelib = cwd / "venv" / "lib" / "python3.12" / "site-packages"
        modules: dict[str, dict[str, str]] = {}
        for module_name in ("js", "js_work"):
            module_file = purelib / module_name / "__init__.py"
            module_file.parent.mkdir(parents=True, exist_ok=True)
            module_file.write_text(f'"""isolated {module_name} fixture."""\n', encoding="utf-8")
            modules[module_name] = {
                "file": str(module_file.resolve()),
                "file_sha256": hashlib.sha256(module_file.read_bytes()).hexdigest(),
                "site_packages": str(purelib.resolve()),
            }
        import_evidence = {"modules": modules, "errors": []}
        stdout = json.dumps(import_evidence) + "\n"
    else:
        stdout = "No broken requirements found.\n" if name.endswith("pip check") else ""
    stderr = ""
    record: dict[str, object] = {
        "step": name,
        "argv": argv,
        "cwd": str(cwd),
        "started_utc": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "finished_utc": finished.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "exit_code": 0,
        "ok": True,
        "source_digest": source_digest,
        "stdout_tail": stdout,
        "stderr_tail": stderr,
        "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
    }
    steps_dir = evidence_dir / "e2e" / "steps"
    steps_dir.mkdir(parents=True, exist_ok=True)
    index = len(tuple(steps_dir.glob("*.receipt.json"))) + 1
    slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    prefix = steps_dir / f"{index:02d}_{slug}"
    stdout_path = prefix.with_suffix(".stdout.txt")
    stderr_path = prefix.with_suffix(".stderr.txt")
    receipt_path = prefix.with_suffix(".receipt.json")
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    record.update(
        {
            "stdout_path": str(stdout_path.resolve()),
            "stderr_path": str(stderr_path.resolve()),
            "step_receipt_path": str(receipt_path.resolve()),
        }
    )
    if name.endswith("pip install artifact offline (echo-tokenizer,office)"):
        report_path = Path(str(argv[9]))
        record["pip_report"] = {
            "path": str(report_path.resolve()),
            "sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
            "packages": [
                {"name": "js-agent", "version": "0", "archive_hash": "sha256=" + "a" * 64}
            ],
        }
    if import_evidence is not None:
        record["import_evidence"] = import_evidence
    receipt_path.write_text(
        json.dumps(
            {
                key: record[key]
                for key in (
                    "argv",
                    "cwd",
                    "exit_code",
                    "stdout_sha256",
                    "stderr_sha256",
                    "stdout_path",
                    "stderr_path",
                    "step_receipt_path",
                )
            }
        ),
        encoding="utf-8",
    )
    if detail is not None:
        record["detail"] = detail
    return record


def _seed_evidence_bundle(root: Path) -> tuple[Path, dict[str, object]]:
    evidence_dir = root / "evidence-bundle"
    artifacts_dir = evidence_dir / "e2e" / "artifacts"
    wheel_meta = _write_artifact(artifacts_dir / "js_agent-0.whl", b"wheel-bytes")
    sdist_meta = _write_artifact(artifacts_dir / "js_agent-0.tar.gz", b"sdist-bytes")
    wheel_meta["path"] = "e2e/artifacts/js_agent-0.whl"
    sdist_meta["path"] = "e2e/artifacts/js_agent-0.tar.gz"
    work_outputs: dict[str, dict[str, object]] = {}
    bindings: dict[str, tuple[list[dict[str, object]], int, str, str, str]] = {}
    manifest = [
        {"path": wheel_meta["path"], "sha256": wheel_meta["sha256"], "bytes": wheel_meta["bytes"]},
        {"path": sdist_meta["path"], "sha256": sdist_meta["sha256"], "bytes": sdist_meta["bytes"]},
    ]
    for index, kind in enumerate(("wheel", "sdist"), start=1):
        work_dir = evidence_dir / "e2e" / "work" / kind
        work_path = work_dir / "iso-e2e.xlsx"
        work_sha = _write_xlsx(work_path, [["iso", "e2e", "leased"]])
        key = bytes([index]) * 32
        journal_path = work_dir / "ledger.journal"
        chain, sequence, record_hash = _build_fixture_ledger_chain(
            journal_path=journal_path,
            mac_key=key,
            output_hash=work_sha,
        )
        journal_sha = hashlib.sha256(journal_path.read_bytes()).hexdigest()
        key_sha = hashlib.sha256(key).hexdigest()
        work_outputs[kind] = {
            "path": f"e2e/work/{kind}/iso-e2e.xlsx",
            "sha256": work_sha,
            "bytes": work_path.stat().st_size,
            "cells": [["iso", "e2e", "leased"]],
        }
        bindings[kind] = (chain, sequence, record_hash, journal_sha, key_sha)
        for relative in (
            f"e2e/work/{kind}/iso-e2e.xlsx",
            f"e2e/work/{kind}/ledger.journal",
        ):
            target = evidence_dir / relative
            manifest.append(
                {
                    "path": relative,
                    "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                    "bytes": target.stat().st_size,
                }
            )
    return evidence_dir, {
        "wheel": wheel_meta,
        "sdist": sdist_meta,
        "work_output": work_outputs["sdist"],
        "work_outputs": work_outputs,
        "bindings": bindings,
        "manifest": manifest,
    }


def _valid_payload(root: Path) -> tuple[Path, dict[str, object]]:
    frozen_key = root / "docs" / "security" / "ECHO_E2E_LEDGER_PUBKEY.json"
    frozen_key.parent.mkdir(parents=True, exist_ok=True)
    # Test-fixture key only — never a production trust root / fixed Round8.7 seed.
    private_key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"js-agent-test-fixture-e2e-ledger-key-v1").digest()
    )
    public_raw = private_key.public_key().public_bytes_raw()
    frozen_key.write_text(
        json.dumps(
            {
                "schema_version": "echo-e2e-ledger-pubkey-v1",
                "algorithm": "Ed25519",
                "public_key_b64": base64.b64encode(public_raw).decode(),
                "fingerprint_sha256": hashlib.sha256(public_raw).hexdigest(),
                "not_a_third_party_signature": True,
                "purpose": "test-fixture-only",
            }
        ),
        encoding="utf-8",
    )
    (root / "js").mkdir(exist_ok=True)
    (root / "js" / "marker.py").write_text("ISO = 1\n", encoding="utf-8")
    (root / "js_work").mkdir(exist_ok=True)
    (root / "js_work" / "marker.py").write_text("ISO = 1\n", encoding="utf-8")
    digest = release_source_digest(root)
    evidence_dir, bundle = _seed_evidence_bundle(root)
    server_details: dict[str, dict[str, object]] = {}
    for kind in ("wheel", "sdist"):
        ledger_chain, ledger_sequence, record_hash, journal_sha, key_sha = bundle["bindings"][kind]
        server_details[kind] = _server_detail(
            output_sha256=str(bundle["work_outputs"][kind]["sha256"]),
            ledger_chain=ledger_chain,
            ledger_sequence=ledger_sequence,
            record_hash=record_hash,
            evidence_kind=kind,
            journal_sha256=journal_sha,
            mac_key_sha256=key_sha,
        )
    results: list[dict[str, object]] = []
    for name in _ISOLATED_VENV_E2E_REQUIRED_STEPS:
        if _ISOLATED_VENV_E2E_SERVER_STEP in name:
            kind = "wheel" if name.startswith("wheel:") else "sdist"
            results.append(
                _step_record(
                    name,
                    source_digest=digest,
                    root=root,
                    evidence_dir=evidence_dir,
                    detail=server_details[kind],
                ),
            )
        else:
            results.append(
                _step_record(
                    name,
                    source_digest=digest,
                    root=root,
                    evidence_dir=evidence_dir,
                )
            )
    payload = {
        "schema_version": _ISOLATED_VENV_E2E_SCHEMA_VERSION,
        "offline": True,
        "ok": True,
        "source_digest": digest,
        "evidence_root": evidence_dir.relative_to(root).as_posix(),
        "artifacts": {"wheel": bundle["wheel"], "sdist": bundle["sdist"]},
        "work_output": bundle["work_output"],
        "work_outputs": bundle["work_outputs"],
        "manifest": bundle["manifest"],
        "pip_check": {
            "wheel": {"ok": True, "exit_code": 0},
            "sdist": {"ok": True, "exit_code": 0},
        },
        "results": results,
    }
    path = evidence_dir / "e2e" / "ECHO_ISOLATED_VENV_E2E.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    provenance = {
        "schema_version": "echo-e2e-ledger-key-provenance-v1",
        "public_fingerprint": hashlib.sha256(public_raw).hexdigest(),
        "generation_method": "random",
        "location_class": "external_temp",
        "private_mode": "0600",
        "public_key_digest_binding": "docs/security/ECHO_E2E_LEDGER_PUBKEY.json",
        "destroyed": True,
        "not_a_third_party_signature": True,
    }
    (evidence_dir / "e2e" / "E2E_KEY_PROVENANCE.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path, payload


def test_valid_isolated_e2e_round85_fixture_accepts_current_schema(tmp_path: Path) -> None:
    path, _payload = _valid_payload(tmp_path)
    assert _valid_isolated_venv_e2e(tmp_path, path)


def test_valid_isolated_e2e_rejects_extra_19th_step(tmp_path: Path) -> None:
    path, payload = _valid_payload(tmp_path)
    payload["results"] = [*payload["results"], {"step": "", "ok": True}]
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert _valid_isolated_venv_e2e(tmp_path, path) is False


def test_valid_isolated_e2e_rejects_reversed_step_order(tmp_path: Path) -> None:
    path, payload = _valid_payload(tmp_path)
    payload["results"] = list(reversed(payload["results"]))
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert _valid_isolated_venv_e2e(tmp_path, path) is False


def test_valid_isolated_e2e_rejects_fake_sha_without_file(tmp_path: Path) -> None:
    path, payload = _valid_payload(tmp_path)
    payload["artifacts"]["wheel"]["sha256"] = "f" * 64
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert _valid_isolated_venv_e2e(tmp_path, path) is False


def test_valid_isolated_e2e_rejects_missing_artifact_file(tmp_path: Path) -> None:
    path, payload = _valid_payload(tmp_path)
    artifact = tmp_path / payload["evidence_root"] / payload["artifacts"]["wheel"]["path"]
    artifact.unlink()
    assert _valid_isolated_venv_e2e(tmp_path, path) is False


def test_valid_isolated_e2e_rejects_tampered_artifact_file(tmp_path: Path) -> None:
    path, payload = _valid_payload(tmp_path)
    artifact = tmp_path / payload["evidence_root"] / payload["artifacts"]["sdist"]["path"]
    artifact.write_bytes(b"tampered")
    assert _valid_isolated_venv_e2e(tmp_path, path) is False


def test_valid_isolated_e2e_rejects_tampered_work_xlsx_cells(tmp_path: Path) -> None:
    path, payload = _valid_payload(tmp_path)
    work_path = tmp_path / payload["evidence_root"] / payload["work_output"]["path"]
    _write_xlsx(work_path, [["bad", "cells"]])
    assert _valid_isolated_venv_e2e(tmp_path, path) is False


def test_verify_work_ledger_receipt_binding_accepts_fixture_chain() -> None:
    ledger_chain, ledger_sequence, record_hash = _build_fixture_ledger_chain()
    receipt = _work_receipt_with_ledger_binding(
        output_sha256="c" * 64,
        ledger_chain=ledger_chain,
        ledger_sequence=ledger_sequence,
        record_hash=record_hash,
    )
    assert _verify_work_ledger_receipt_binding(receipt) is True


def test_build_work_ledger_receipt_binding_reads_real_journal(tmp_path: Path) -> None:
    from js.echo.ledger.journal import _record_to_json

    owner = "iso-e2e-owner"
    run_id = "iso-e2e-work-run"
    state_dir = tmp_path / "state"
    partition_root = (
        state_dir
        / "echo"
        / "ledger"
        / "partitions"
        / "product_test"
        / "owner_test"
        / "session_test"
    )
    partition_root.mkdir(parents=True)
    journal_path = partition_root / "chat.jsonl"
    mac_key = b"\x02" * 32
    (partition_root / "journal.key").write_bytes(mac_key.hex().encode("ascii"))
    ledger_chain, _ledger_sequence, _record_hash = _build_fixture_ledger_chain(
        owner=owner,
        run_id=run_id,
    )
    journal = EchoJournal(mac_key=mac_key)
    for row in ledger_chain:
        journal.append(
            record_type=str(row["record_type"]),
            tenant_id=str(row["tenant_id"]),
            run_id=str(row["run_id"]),
            payload=dict(row["payload"]),
        )
    with journal_path.open("w", encoding="utf-8") as handle:
        for record in journal.records:
            handle.write(_record_to_json(record) + "\n")

    binding = build_work_ledger_receipt_binding(
        journal_path=journal_path,
        mac_key=mac_key,
        state_dir=state_dir,
        owner=owner,
        session="iso-e2e-work",
        product_id="js-work",
        run_id=run_id,
        tool_name="excel_write",
    )
    assert binding is not None
    assert binding["lease_consumed"] is True
    assert binding["terminal_status"] == "ok"
    assert binding["effect_id"] == "effect-iso-e2e-work"


@pytest.mark.asyncio
async def test_build_work_ledger_binding_tolerates_intervening_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real excel_write journals insert approval rows between outbox_claimed and receipt."""
    monkeypatch.setenv("HOME", str(tmp_path))
    from js.echo.effect_interpreter import ToolEffect
    from js.security.approvals import ApprovalDecision, ApprovalDecisionType
    from js_work.agent_factory import create_work_agent
    from js_work.config import WorkSettings
    from js_work.tools import WorkToolProfile

    work_home = tmp_path / ".js-work"
    settings = WorkSettings(
        work_home=work_home,
        workspace=work_home / "workspace",
        state_dir=work_home / "state",
        echo_engine="on",
        providers=[],
        models=[],
    )
    agent = create_work_agent(settings=settings, profile=WorkToolProfile.OFFICE)
    owner = "iso-e2e-owner"
    session = "iso-e2e-work"
    run_id = "iso-e2e-work-run"
    owner_root = settings.workspace / "owners" / owner_slug(owner) / session_slug(session)
    owner_root.mkdir(parents=True, exist_ok=True)
    arguments = {
        "path": "outputs/iso-e2e.xlsx",
        "data": '[["iso", "e2e", "leased"]]',
        "start_cell": "A1",
    }

    def _approve(request: object) -> ApprovalDecision:
        return ApprovalDecision(
            ApprovalDecisionType.APPROVE,
            request_id=str(getattr(request, "id", "")),
            reason="round85-intervening-approval",
        )

    agent.approvals.set_callback(
        session,
        _approve,
        owner_key_hash=owner,
        run_id=run_id,
        tool_name="excel_write",
        arguments=arguments,
    )
    context = agent.echo_runtime.build_context(
        channel="web",
        owner_key_hash=owner,
        session_id=session,
        run_id=run_id,
    )
    effect = ToolEffect.from_arguments(
        "excel_write",
        arguments,
        allowed_tools=("excel_write",),
    )
    _message, result = await agent.echo_runtime.execute_tool_effect(effect, context)
    assert result.success is True
    journal_path = agent.echo_safety_service.journal_path_for_scope(
        owner,
        product_id="js-work",
        session_id=session,
    )
    mac_key = agent.echo_safety_service.journal_key_for_scope(
        owner,
        product_id="js-work",
        session_id=session,
    )
    binding = build_work_ledger_receipt_binding(
        journal_path=journal_path,
        mac_key=mac_key,
        state_dir=settings.state_dir,
        owner=owner,
        session=session,
        product_id="js-work",
        run_id=run_id,
        tool_name="excel_write",
    )
    await agent.close()
    assert binding is not None
    assert binding["lease_consumed"] is True
    assert binding["tool_name"] == "excel_write"
    assert isinstance(binding["lease_id"], str) and len(str(binding["lease_id"])) >= 16
    assert _verify_work_ledger_receipt_binding(
        {
            "product_id": "js-work",
            "owner": owner,
            "session": session,
            "run_id": run_id,
            "tool_name": "excel_write",
            "lease_consumed": True,
            **{k: binding[k] for k in binding},
        }
    )


def _work_receipt_from_payload(payload: dict[str, object]) -> dict[str, object]:
    return next(
        step
        for step in payload["results"]
        if step["step"].startswith("wheel:") and _ISOLATED_VENV_E2E_SERVER_STEP in step["step"]
    )["detail"]["work_receipt"]


@pytest.mark.parametrize(
    ("mutator", "label"),
    [
        (lambda receipt: receipt.update({"lease_id": "b" * 32}), "lease_id"),
        (lambda receipt: receipt.update({"run_id": "other-run"}), "run_id"),
        (lambda receipt: receipt.update({"owner": "other-owner"}), "owner"),
        (lambda receipt: receipt.update({"session": "other-session"}), "session"),
        (lambda receipt: receipt.update({"tool_name": "file_read"}), "tool_name"),
        (lambda receipt: receipt.update({"terminal_status": "failed"}), "terminal_status"),
        (lambda receipt: receipt.update({"effect_id": "other-effect"}), "effect_id"),
        (lambda receipt: receipt.update({"record_hash": "e" * 64}), "record_hash"),
        (lambda receipt: receipt.update({"ledger_sequence": 999}), "ledger_sequence"),
        (
            lambda receipt: receipt["ledger_chain"][0].update({"record_hash": "f" * 64}),
            "ledger_chain_hash",
        ),
        (lambda receipt: receipt.update({"lease_consumed": False}), "lease_consumed"),
    ],
)
def test_work_receipt_ledger_binding_negative_controls(
    tmp_path: Path,
    mutator: object,
    label: str,
) -> None:
    path, payload = _valid_payload(tmp_path)
    receipt = _work_receipt_from_payload(payload)
    mutator(receipt)  # type: ignore[operator]
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert _valid_isolated_venv_e2e(tmp_path, path) is False
