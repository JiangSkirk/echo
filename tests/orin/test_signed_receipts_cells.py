"""K§8.5 signed receipts attach on Build/File/Services helper paths."""

from __future__ import annotations

import hashlib
import json

import pytest

from js.orin.draft import SIGNED_RECEIPT_SCHEMA, signed_receipt_from_dict
from js.orin.protocol import ProtocolError, canonical_json
from js.orind.cells.base import CellBase


def test_cell_base_attaches_signed_receipt() -> None:
    cell = CellBase.__new__(CellBase)
    cell._session_key = b"k" * 32
    cell._mac_key = b"k" * 32
    public = {"status": "COMMITTED", "files": ["a.txt"]}
    sealed = cell.attach_signed_receipt(
        public,
        permit_id="permit:1",
        executor_id="cell.file",
        effect_hash="sha256:" + "a" * 64,
        receipt_id="receipt:1",
    )
    parsed = json.loads(sealed["signed_receipt"])
    assert parsed["schema"] == SIGNED_RECEIPT_SCHEMA
    checked = signed_receipt_from_dict(parsed, mac_key=b"k" * 32)
    assert checked.receipt.executor_id == "cell.file"
    assert checked.receipt.permit_id == "permit:1"
    digest = "sha256:" + hashlib.sha256(canonical_json(public).encode("utf-8")).hexdigest()
    assert checked.receipt.result_digest == digest


def test_cell_base_skips_unsigned_without_key() -> None:
    cell = CellBase.__new__(CellBase)
    cell._session_key = None
    public = {"status": "COMMITTED"}
    assert (
        cell.attach_signed_receipt(
            public,
            permit_id="p",
            executor_id="cell.build",
            effect_hash="sha256:" + "0" * 64,
            receipt_id="r",
        )
        == public
    )


def test_cross_cell_receipt_fails_verify() -> None:
    cell = CellBase.__new__(CellBase)
    cell._session_key = b"k" * 32
    sealed = cell.attach_signed_receipt(
        {"status": "COMMITTED"},
        permit_id="p",
        executor_id="cell.build",
        effect_hash="sha256:" + "0" * 64,
        receipt_id="r",
    )
    parsed = json.loads(sealed["signed_receipt"])
    with pytest.raises(ProtocolError):
        signed_receipt_from_dict(parsed, mac_key=b"x" * 32)
