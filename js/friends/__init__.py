"""Friends and Agent collaboration framework.

R7 scope:
- Friend L1: QR invite, mutual confirmation, E2E encrypted text,
  delivery/revoke/block/anti-replay/key rotation.
- Agent L2: RemoteTaskEnvelope + CollaborationGrant, text and bounded JSON only,
  default tools empty, forced deadline/token/cost/byte/count limits,
  no recursive delegation.

No public search, no centralized offline queue, no group chat,
no auto attachments, no friend direct tool invocation.
"""

from __future__ import annotations

from js.friends.manager import FriendManager
from js.friends.protocol import (
    CollaborationGrant,
    CollaborationResult,
    FriendMessage,
    FriendMessageStatus,
    FriendRequest,
    FriendStatus,
    RemoteTaskEnvelope,
)

__all__ = [
    "CollaborationGrant",
    "CollaborationResult",
    "FriendManager",
    "FriendMessage",
    "FriendMessageStatus",
    "FriendRequest",
    "FriendStatus",
    "RemoteTaskEnvelope",
]
