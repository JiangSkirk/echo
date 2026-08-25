"""Handle Broker (K§7.3 / M§3.2-2): mint, seal and resolve permission objects.

Echo may only *select* among visible candidates; it can never mint a new
permission object by emitting a similar string because every handle carries
an orind-computed HMAC seal over its canonical payload. New objects enter
the world only through a one-time approval and are then registered as seeds
so open-ended tasks do not dead-end on an empty candidate set.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Iterable
from typing import Any

from js.orin.handles import (
    HANDLE_KINDS,
    OriginHandle,
    SeedCandidate,
    handle_from_dict,
    make_handle_id,
)
from js.orind.store import OrinStore


class HandleBroker:
    """Issues and resolves sealed handles over the WAL ``handles`` table."""

    def __init__(
        self,
        *,
        store: OrinStore,
        mac_key: bytes,
        issuer: str = "orind:broker",
        default_ttl_ms: int = 24 * 60 * 60 * 1000,
    ) -> None:
        self._store = store
        self._mac_key = mac_key
        self._issuer = issuer
        self._default_ttl_ms = default_ttl_ms

    # -- issuance ---------------------------------------------------------------
    def issue(
        self,
        *,
        kind: str,
        token: str,
        owner_key_hash: str,
        tenant: str = "personal",
        source_class: str = "USER_AUTHENTICATED",
        integrity: str = "trusted_local_object",
        confidentiality: str = "CONFIDENTIAL",
        object_digest: str = "",
        capabilities: tuple[str, ...] = ("read",),
        expires_at_ms: int | None = None,
        approved: bool = False,
        now_ms: int | None = None,
    ) -> dict[str, Any]:
        """Mint one sealed handle. ``approved=False`` refuses non-seed kinds.

        DesktopTargetHandle is type-only in Stage B and never issued.
        """

        if kind not in HANDLE_KINDS or kind == "DesktopTargetHandle":
            return {"ok": False, "code": "unknown_handle", "reason": f"kind {kind!r} not issuable"}
        now = time.time_ns() // 1_000_000 if now_ms is None else now_ms
        if not approved:
            return {
                "ok": False,
                "code": "approval_required",
                "reason": "new handle objects require one-time user approval",
            }
        try:
            handle_id = make_handle_id(kind, token)
        except Exception as exc:
            return {"ok": False, "code": "bad_message", "reason": str(exc)}
        expiry = now + self._default_ttl_ms if expires_at_ms is None else expires_at_ms
        base = OriginHandle(
            handle_id=handle_id,
            kind=kind,
            owner_key_hash=owner_key_hash,
            tenant=tenant,
            source_class=source_class,
            integrity=integrity,
            confidentiality=confidentiality,
            object_digest=object_digest,
            capabilities=tuple(capabilities),
            issuer=self._issuer,
            created_at_ms=now,
            expires_at_ms=expiry,
        )
        sealed = base.sealed_by(self._mac_key, self._issuer, now)
        self._store.record_handle(
            handle_id=sealed.handle_id, kind=sealed.kind, payload=sealed.to_dict()
        )
        self._store.add_seed(
            kind=kind,
            token=token,
            label=token,
            source="one_time_approval",
            added_at_ms=now,
        )
        return {"ok": True, "handle": sealed.to_dict()}

    def register_desktop_cell_handle(
        self,
        raw_handle: dict[str, Any],
        *,
        cell_session_key: bytes,
        expected_handle_id: str,
        owner_key_hash: str,
        tenant: str,
        expires_at_ms: int,
        now_ms: int | None = None,
    ) -> dict[str, Any]:
        """Accept one target sealed by the authenticated Desktop Cell.

        This is an internal cells.sock path, not a general issuance API.  The
        Cell proves that the target came from its private observation report;
        orind then re-seals the exact payload with the broker key so ordinary
        package resolution can keep using the existing OriginHandle contract.
        """

        now = time.time_ns() // 1_000_000 if now_ms is None else now_ms
        try:
            proposed = handle_from_dict(raw_handle, require_signature=True)
        except Exception as exc:
            return {"ok": False, "code": "unknown_handle", "reason": str(exc)}
        if (
            proposed.kind != "DesktopTargetHandle"
            or proposed.handle_id != expected_handle_id
            or proposed.issuer != "cell:desktop"
            or proposed.owner_key_hash != owner_key_hash
            or proposed.tenant != tenant
            or proposed.source_class != "TRUSTED_LOCAL"
            or proposed.integrity != "trusted_local_object"
            or proposed.confidentiality != "CONFIDENTIAL"
            or proposed.capabilities != ("read", "use")
            or proposed.expires_at_ms != expires_at_ms
            or proposed.created_at_ms > now + 5_000
            or proposed.created_at_ms < now - 65_000
            or proposed.expires_at_ms <= now
            or not proposed.object_digest.startswith("sha256:")
            or len(proposed.object_digest) != 71
            or not proposed.verify_seal(cell_session_key)
        ):
            return {
                "ok": False,
                "code": "unknown_handle",
                "reason": "Desktop Cell handle binding is invalid",
            }
        final = OriginHandle(
            handle_id=proposed.handle_id,
            kind=proposed.kind,
            owner_key_hash=proposed.owner_key_hash,
            tenant=proposed.tenant,
            source_class=proposed.source_class,
            integrity=proposed.integrity,
            confidentiality=proposed.confidentiality,
            object_digest=proposed.object_digest,
            capabilities=proposed.capabilities,
            issuer=proposed.issuer,
            created_at_ms=proposed.created_at_ms,
            expires_at_ms=proposed.expires_at_ms,
        ).sealed_by(self._mac_key, "cell:desktop", proposed.created_at_ms)
        status = self._store.record_handle_immutable(
            handle_id=final.handle_id,
            kind=final.kind,
            payload=final.to_dict(),
        )
        if status == "conflict":
            return {
                "ok": False,
                "code": "unknown_handle",
                "reason": "Desktop Cell handle id conflicts with existing content",
            }
        return {"ok": True, "handle": final.to_dict(), "status": status}

    # -- resolution ----------------------------------------------------------------
    def resolve(self, handle_id: str, *, now_ms: int | None = None) -> dict[str, Any]:
        raw = self._store.get_handle(handle_id)
        if raw is None:
            return {"ok": False, "code": "unknown_handle", "reason": handle_id}
        handle = handle_from_dict(raw, require_signature=True)
        if not handle.verify_seal(self._mac_key):
            return {"ok": False, "code": "unknown_handle", "reason": "seal invalid"}
        now = time.time_ns() // 1_000_000 if now_ms is None else now_ms
        if now >= handle.expires_at_ms:
            return {"ok": False, "code": "expired", "reason": "handle expired"}
        return {"ok": True, "handle": handle.to_dict()}

    def valid_handle(self, handle_id: str, *, now_ms: int) -> OriginHandle | None:
        result = self.resolve(handle_id, now_ms=now_ms)
        if not result.get("ok"):
            return None
        return handle_from_dict(result["handle"], require_signature=True)

    # -- seeding -----------------------------------------------------------------
    def seed_list(self, kind: str | None = None) -> list[dict[str, Any]]:
        return self._store.seed_candidates(kind)

    def add_seed_candidate(self, candidate: SeedCandidate, *, added_at_ms: int) -> bool:
        return self._store.add_seed(
            kind=candidate.kind,
            token=candidate.token,
            label=candidate.label,
            source=candidate.source,
            added_at_ms=added_at_ms,
        )

    def seed_from_sources(
        self,
        *,
        contacts: Iterable[dict[str, Any]] = (),
        history: Iterable[dict[str, Any]] = (),
        cron_templates: Iterable[Any] = (),
        now_ms: int | None = None,
    ) -> int:
        """Populate candidate seeds from user-owned sources (M§3.2-2).

        ``contacts`` rows come from FriendManager.list_friends();
        ``history`` dicts carry {"recipient": "<kind>:<token>"} or
        {"email": "…"}; cron templates expose ``default_payload`` possibly
        containing "recipient"/"recipients" values. Returns the number of
        NEW candidates. Seeded handles are still permission objects — Echo
        may only SELECT among them, never mint.
        """

        import time as _time

        ts = int(_time.time() * 1000) if now_ms is None else now_ms
        added = 0

        def _add(kind: str, token: str, label: str, source: str) -> None:
            nonlocal added
            if not token:
                return
            if self.add_seed_candidate(
                SeedCandidate(kind=kind, token=token, label=label, source=source),
                added_at_ms=ts,
            ):
                added += 1

        for friend in contacts:
            if not isinstance(friend, dict):
                continue
            friend_id = str(friend.get("friend_id") or "")
            if not friend_id:
                continue
            label = str(friend.get("display_name") or friend_id)
            _add("RecipientHandle", f"friend-{friend_id}", label, "contacts")

        for record in history:
            if not isinstance(record, dict):
                continue
            recipient = str(record.get("recipient") or "")
            email = str(record.get("email") or "")
            if recipient.startswith("rcpt:"):
                _add("RecipientHandle", recipient.split(":", 1)[1], recipient, "task_history")
            elif email and "@" in email and " " not in email:
                local, _, domain = email.partition("@")
                digest = hashlib.sha256(email.encode("utf-8")).hexdigest()[:16]
                _add(
                    "RecipientHandle",
                    f"hist-{digest}",
                    email,
                    "task_history",
                )
                _ = local, domain

        for template in cron_templates:
            payload = getattr(template, "default_payload", None)
            if not isinstance(payload, dict):
                continue
            raw = payload.get("recipients") or payload.get("recipient") or []
            values = raw if isinstance(raw, list) else [raw]
            for value in values:
                text = str(value)
                if text.startswith("rcpt:"):
                    _add("RecipientHandle", text.split(":", 1)[1], text, "cron_template")
                elif text and "@" in text and " " not in text:
                    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
                    _add("RecipientHandle", f"cron-{digest}", text, "cron_template")
        return added


__all__ = ["HandleBroker"]
