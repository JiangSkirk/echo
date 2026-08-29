"""Friends store: truncated DB, replay after crash, and ENOSPC."""

from __future__ import annotations

import errno
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from js.friends.protocol import FriendStatus
from js.friends.store import FriendStore, StoredFriend


def _friend(owner: str, friend_id: str) -> StoredFriend:
    return StoredFriend(
        owner=owner,
        friend_id=friend_id,
        display_name=friend_id,
        public_key="pk",
        endpoint="http://127.0.0.1:9",
        status=FriendStatus.CONFIRMED,
        key_rotation_epoch=1,
        confirmed_at=1.0,
    )


def test_seen_ids_do_not_cross_owners_after_restart(tmp_path: Path) -> None:
    store = FriendStore(tmp_path)
    store.mark_seen("owner-a", "msg-1")
    store.add_message(
        "owner-a",
        message_id="msg-1",
        friend_id="f-1",
        direction="in",
        ciphertext="cipher-a",
        epoch=1,
    )
    revived = FriendStore(tmp_path)
    assert revived.seen("owner-a", "msg-1") is True
    assert revived.seen("owner-b", "msg-1") is False
    assert revived.list_messages("owner-b", "f-1") == []
    assert revived.list_messages("owner-a", "f-1")[0]["message_id"] == "msg-1"


def test_truncated_friends_db_fails_closed(tmp_path: Path) -> None:
    store = FriendStore(tmp_path)
    store.upsert_friend(_friend("owner-a", "f-1"))
    store.db_path.write_bytes(store.db_path.read_bytes()[:30])
    with pytest.raises(sqlite3.Error):
        store.list_friends("owner-a")
    with pytest.raises(sqlite3.Error):
        store.get_friend("owner-b", "f-1")


def test_enospc_on_friend_upsert_does_not_insert(tmp_path: Path) -> None:
    store = FriendStore(tmp_path)
    with patch("js.friends.store.db_connection") as connect:
        conn = connect.return_value.__enter__.return_value
        conn.execute.side_effect = OSError(errno.ENOSPC, "No space left on device")
        with pytest.raises(OSError, match="No space left"):
            store.upsert_friend(_friend("owner-a", "f-1"))
    clean = FriendStore(tmp_path)
    assert clean.list_friends("owner-a") == []
