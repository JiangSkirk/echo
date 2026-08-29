"""Private control-plane handoff vaults for ToolExecutorMixin."""

# mypy: disable-error-code="attr-defined"

from __future__ import annotations

import copy
import json
import threading
from typing import TYPE_CHECKING, Any

from js.agent.base import AgentBase
from js.echo import stable_payload_hash
from js.echo.private_handoff import PrivateHandoffVault
from js.echo.turn_context import current_runtime_context

if TYPE_CHECKING:
    from collections.abc import Callable


class ToolHandoffMixin(AgentBase):
    """One-time private handoff staging for control-plane tools."""

    _private_handoff_init_lock = threading.RLock()
    _private_handoff_ttl_seconds = 300.0
    _private_handoff_max_json_bytes = 1_048_576
    _private_handoff_max_result_text_bytes = 262_144

    def _private_handoff_vault(
        self,
        vault_name: str,
        *,
        max_entries: int,
        cleanup: Callable[[Any], None] | None = None,
    ) -> PrivateHandoffVault[Any]:
        """Return one lazily initialized, thread-safe private handoff vault."""
        with self._private_handoff_init_lock:
            vault = getattr(self, vault_name, None)
            if not isinstance(vault, PrivateHandoffVault):
                vault = PrivateHandoffVault(
                    max_entries=max_entries,
                    ttl_seconds=self._private_handoff_ttl_seconds,
                    cleanup=cleanup,
                )
                setattr(self, vault_name, vault)
        return vault

    def stage_provider_discovery_key(
        self,
        api_key: str,
        *,
        owner_key_hash: str = "",
        product_id: str = "",
        session_id: str = "",
    ) -> str:
        """Keep a provider key in a bounded one-shot in-memory slot.

        The returned opaque reference may enter an Echo tool effect; the
        credential itself must never enter tool arguments, audit events, or
        durable receipts.
        """
        if not isinstance(api_key, str) or not api_key:
            return ""
        vault = self._private_handoff_vault(
            "_provider_discovery_keys",
            max_entries=32,
        )
        partition = self._control_handoff_partition(
            owner_key_hash,
            product_id=product_id,
            session_id=session_id,
        )
        if not partition:
            return ""
        return vault.stage(partition, api_key)

    def take_provider_discovery_key(
        self,
        reference: str,
        *,
        owner_key_hash: str = "",
        product_id: str = "",
        session_id: str = "",
    ) -> str | None:
        """Consume one staged provider credential exactly once."""
        vault = self._private_handoff_vault(
            "_provider_discovery_keys",
            max_entries=32,
        )
        partition = self._control_handoff_partition(
            owner_key_hash,
            product_id=product_id,
            session_id=session_id,
        )
        if not partition:
            return None
        value = vault.take(reference, partition)
        return value if isinstance(value, str) else None

    def discard_provider_discovery_key(
        self,
        reference: str,
        *,
        owner_key_hash: str = "",
        product_id: str = "",
        session_id: str = "",
    ) -> None:
        """Drop an unused one-shot provider credential."""
        vault = self._private_handoff_vault(
            "_provider_discovery_keys",
            max_entries=32,
        )
        partition = self._control_handoff_partition(
            owner_key_hash,
            product_id=product_id,
            session_id=session_id,
        )
        if partition:
            vault.discard(reference, partition)

    def stage_setup_admin_key(
        self,
        admin_key: str,
        *,
        owner_key_hash: str = "",
        product_id: str = "",
        session_id: str = "",
    ) -> str:
        """Stage a newly-created bootstrap key behind a bounded opaque handle."""
        if not isinstance(admin_key, str) or not admin_key:
            return ""
        vault = self._private_handoff_vault(
            "_setup_admin_keys",
            max_entries=8,
        )
        partition = self._control_handoff_partition(
            owner_key_hash,
            product_id=product_id,
            session_id=session_id,
        )
        if not partition:
            return ""
        return vault.stage(partition, admin_key)

    def take_setup_admin_key(
        self,
        reference: str,
        *,
        owner_key_hash: str = "",
        product_id: str = "",
        session_id: str = "",
    ) -> str | None:
        """Consume a setup bootstrap key exactly once without journaling it."""
        vault = self._private_handoff_vault(
            "_setup_admin_keys",
            max_entries=8,
        )
        partition = self._control_handoff_partition(
            owner_key_hash,
            product_id=product_id,
            session_id=session_id,
        )
        if not partition:
            return None
        value = vault.take(reference, partition)
        return value if isinstance(value, str) else None

    def _copy_control_dict(
        self,
        value: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Copy JSON data only when it fits the private handoff budget."""
        try:
            encoded = json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError):
            return None
        if len(encoded) > self._private_handoff_max_json_bytes:
            return None
        return copy.deepcopy(value)

    def _bounded_control_result(self, value: dict[str, Any]) -> dict[str, Any]:
        """Produce a result that always fits a previously reserved slot."""
        copied = self._copy_control_dict(value)
        if copied is not None:
            return copied
        return {
            "success": bool(value.get("success", True)),
            "result_truncated": True,
        }

    def _bounded_control_text(self, value: Any) -> tuple[str, bool]:
        """Return UTF-8-safe text bounded for a private result handoff."""
        if value is None:
            return "", False
        if not isinstance(value, str):
            return "", True
        encoded = value.encode("utf-8")
        maximum = self._private_handoff_max_result_text_bytes
        if len(encoded) <= maximum:
            return value, False
        return encoded[:maximum].decode("utf-8", errors="ignore"), True

    def _control_handoff_partition(
        self,
        owner_key_hash: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> str:
        """Bind one private handoff to product + owner + session."""
        if not isinstance(owner_key_hash, str):
            return ""
        context = current_runtime_context()
        if not owner_key_hash and context is not None:
            owner_key_hash = context.owner_key_hash
        if not owner_key_hash:
            return ""
        if context is not None:
            if context.owner_key_hash != owner_key_hash:
                return ""
            if product_id and product_id != context.product_id:
                return ""
            if session_id and session_id != context.session_id:
                return ""
            product_id = context.product_id
            session_id = context.session_id
        if not product_id:
            product_id = str(getattr(self.settings, "product_id", "js-agent"))
        if (
            not product_id
            or len(product_id) > 512
            or not session_id
            or len(session_id) > 512
            or len(owner_key_hash) > 512
        ):
            return ""
        return stable_payload_hash(
            {
                "product_id": product_id,
                "owner_key_hash": owner_key_hash,
                "session_id": session_id,
            }
        )

    def _stage_memory_control_value(
        self,
        vault_name: str,
        owner_key_hash: str,
        value: dict[str, Any],
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> str:
        """Stage bounded JSON data behind a partition-bound opaque handle."""
        if not isinstance(owner_key_hash, str) or not owner_key_hash or not isinstance(value, dict):
            return ""
        partition = self._control_handoff_partition(
            owner_key_hash,
            product_id=product_id,
            session_id=session_id,
        )
        if not partition:
            return ""
        copied = self._copy_control_dict(value)
        if copied is None:
            return ""
        vault = self._private_handoff_vault(vault_name, max_entries=64)
        return vault.stage(partition, copied)

    def _stage_memory_control_result(
        self,
        vault_name: str,
        owner_key_hash: str,
        value: dict[str, Any],
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> str:
        partition = self._control_handoff_partition(
            owner_key_hash,
            product_id=product_id,
            session_id=session_id,
        )
        if not partition:
            return ""
        vault = self._private_handoff_vault(vault_name, max_entries=64)
        return vault.stage(partition, self._bounded_control_result(value))

    def _reserve_memory_control_result(
        self,
        vault_name: str,
        owner_key_hash: str,
    ) -> str:
        partition = self._control_handoff_partition(owner_key_hash)
        if not partition:
            return ""
        vault = self._private_handoff_vault(vault_name, max_entries=64)
        return vault.reserve(partition)

    def _commit_memory_control_result(
        self,
        vault_name: str,
        reference: str,
        owner_key_hash: str,
        value: dict[str, Any],
    ) -> bool:
        partition = self._control_handoff_partition(owner_key_hash)
        if not partition:
            return False
        vault = self._private_handoff_vault(vault_name, max_entries=64)
        return vault.commit(
            reference,
            partition,
            self._bounded_control_result(value),
        )

    def _take_memory_control_value(
        self,
        vault_name: str,
        reference: str,
        owner_key_hash: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> dict[str, Any] | None:
        partition = self._control_handoff_partition(
            owner_key_hash,
            product_id=product_id,
            session_id=session_id,
        )
        if not partition:
            return None
        vault = self._private_handoff_vault(vault_name, max_entries=64)
        value = vault.take(reference, partition)
        return copy.deepcopy(value) if isinstance(value, dict) else None

    def _discard_memory_control_value(
        self,
        vault_name: str,
        reference: str,
        owner_key_hash: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> None:
        partition = self._control_handoff_partition(
            owner_key_hash,
            product_id=product_id,
            session_id=session_id,
        )
        if not partition:
            return
        vault = self._private_handoff_vault(vault_name, max_entries=64)
        vault.discard(reference, partition)

    def stage_memory_mutation_payload(
        self,
        owner_key_hash: str,
        payload: dict[str, Any],
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> str:
        """Stage private memory input without placing it in an Echo receipt."""
        return self._stage_memory_control_value(
            "_memory_mutation_payloads",
            owner_key_hash,
            payload,
            product_id=product_id,
            session_id=session_id,
        )

    def take_memory_mutation_payload(
        self,
        reference: str,
        owner_key_hash: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> dict[str, Any] | None:
        return self._take_memory_control_value(
            "_memory_mutation_payloads",
            reference,
            owner_key_hash,
            product_id=product_id,
            session_id=session_id,
        )

    def discard_memory_mutation_payload(
        self,
        reference: str,
        owner_key_hash: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> None:
        self._discard_memory_control_value(
            "_memory_mutation_payloads",
            reference,
            owner_key_hash,
            product_id=product_id,
            session_id=session_id,
        )

    def stage_memory_mutation_result(
        self,
        owner_key_hash: str,
        result: dict[str, Any],
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> str:
        """Stage private memory output for one-time HTTP handoff."""
        return self._stage_memory_control_result(
            "_memory_mutation_results",
            owner_key_hash,
            result,
            product_id=product_id,
            session_id=session_id,
        )

    def take_memory_mutation_result(
        self,
        reference: str,
        owner_key_hash: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> dict[str, Any] | None:
        return self._take_memory_control_value(
            "_memory_mutation_results",
            reference,
            owner_key_hash,
            product_id=product_id,
            session_id=session_id,
        )

    def stage_skill_mutation_payload(
        self,
        owner_key_hash: str,
        payload: dict[str, Any],
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> str:
        """Stage private skill-control input outside durable Echo records."""
        return self._stage_memory_control_value(
            "_skill_mutation_payloads",
            owner_key_hash,
            payload,
            product_id=product_id,
            session_id=session_id,
        )

    def take_skill_mutation_payload(
        self,
        reference: str,
        owner_key_hash: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> dict[str, Any] | None:
        return self._take_memory_control_value(
            "_skill_mutation_payloads",
            reference,
            owner_key_hash,
            product_id=product_id,
            session_id=session_id,
        )

    def discard_skill_mutation_payload(
        self,
        reference: str,
        owner_key_hash: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> None:
        self._discard_memory_control_value(
            "_skill_mutation_payloads",
            reference,
            owner_key_hash,
            product_id=product_id,
            session_id=session_id,
        )

    def stage_skill_mutation_result(
        self,
        owner_key_hash: str,
        result: dict[str, Any],
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> str:
        return self._stage_memory_control_result(
            "_skill_mutation_results",
            owner_key_hash,
            result,
            product_id=product_id,
            session_id=session_id,
        )

    def take_skill_mutation_result(
        self,
        reference: str,
        owner_key_hash: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> dict[str, Any] | None:
        return self._take_memory_control_value(
            "_skill_mutation_results",
            reference,
            owner_key_hash,
            product_id=product_id,
            session_id=session_id,
        )

    def stage_evolution_action_result(
        self,
        owner_key_hash: str,
        result: dict[str, Any],
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> str:
        return self._stage_memory_control_result(
            "_evolution_action_results",
            owner_key_hash,
            result,
            product_id=product_id,
            session_id=session_id,
        )

    def take_evolution_action_result(
        self,
        reference: str,
        owner_key_hash: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> dict[str, Any] | None:
        return self._take_memory_control_value(
            "_evolution_action_results",
            reference,
            owner_key_hash,
            product_id=product_id,
            session_id=session_id,
        )

    def stage_upload_commit(
        self,
        owner_key_hash: str,
        session_id: str,
        writer: Any,
    ) -> str:
        """Stage a streamed upload writer behind an owner-bound one-shot handle."""
        from js.echo.attachment_gate import SecureUploadWriter

        if (
            not isinstance(owner_key_hash, str)
            or not owner_key_hash
            or not isinstance(session_id, str)
            or not session_id.strip()
            or len(session_id) > 256
            or not isinstance(writer, SecureUploadWriter)
        ):
            return ""
        vault = self._private_handoff_vault(
            "_upload_commit_writers",
            max_entries=16,
            cleanup=self._close_upload_handoff,
        )
        partition = self._control_handoff_partition(
            owner_key_hash,
            session_id=session_id,
        )
        if not partition:
            return ""
        return vault.stage(partition, (session_id, writer))

    @staticmethod
    def _close_upload_handoff(value: Any) -> None:
        if not isinstance(value, tuple) or len(value) != 2:
            return
        close = getattr(value[1], "close", None)
        if callable(close):
            close()

    def take_upload_commit(
        self,
        reference: str,
        owner_key_hash: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> tuple[str, Any] | None:
        """Consume one streamed upload writer exactly once for its owner."""
        from js.echo.attachment_gate import SecureUploadWriter

        vault = self._private_handoff_vault(
            "_upload_commit_writers",
            max_entries=16,
            cleanup=self._close_upload_handoff,
        )
        partition = self._control_handoff_partition(
            owner_key_hash,
            product_id=product_id,
            session_id=session_id,
        )
        if not partition:
            return None
        entry = vault.take(reference, partition)
        if not isinstance(entry, tuple) or len(entry) != 2:
            return None
        session_id, writer = entry
        if not isinstance(session_id, str) or not isinstance(writer, SecureUploadWriter):
            return None
        return session_id, writer

    def discard_upload_commit(
        self,
        reference: str,
        owner_key_hash: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> None:
        """Discard an unconsumed streamed upload handoff."""
        vault = self._private_handoff_vault(
            "_upload_commit_writers",
            max_entries=16,
            cleanup=self._close_upload_handoff,
        )
        partition = self._control_handoff_partition(
            owner_key_hash,
            product_id=product_id,
            session_id=session_id,
        )
        if partition:
            vault.discard(reference, partition)

    def stage_upload_mutation_payload(
        self,
        owner_key_hash: str,
        payload: dict[str, Any],
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> str:
        """Stage private upload metadata outside the Echo receipt."""
        return self._stage_memory_control_value(
            "_upload_mutation_payloads",
            owner_key_hash,
            payload,
            product_id=product_id,
            session_id=session_id,
        )

    def take_upload_mutation_payload(
        self,
        reference: str,
        owner_key_hash: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> dict[str, Any] | None:
        return self._take_memory_control_value(
            "_upload_mutation_payloads",
            reference,
            owner_key_hash,
            product_id=product_id,
            session_id=session_id,
        )

    def discard_upload_mutation_payload(
        self,
        reference: str,
        owner_key_hash: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> None:
        self._discard_memory_control_value(
            "_upload_mutation_payloads",
            reference,
            owner_key_hash,
            product_id=product_id,
            session_id=session_id,
        )

    def stage_upload_mutation_result(
        self,
        owner_key_hash: str,
        result: dict[str, Any],
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> str:
        """Stage private upload response metadata for one-time handoff."""
        return self._stage_memory_control_result(
            "_upload_mutation_results",
            owner_key_hash,
            result,
            product_id=product_id,
            session_id=session_id,
        )

    def take_upload_mutation_result(
        self,
        reference: str,
        owner_key_hash: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> dict[str, Any] | None:
        return self._take_memory_control_value(
            "_upload_mutation_results",
            reference,
            owner_key_hash,
            product_id=product_id,
            session_id=session_id,
        )

    def stage_cron_mutation_payload(
        self,
        owner_key_hash: str,
        payload: dict[str, Any],
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> str:
        """Stage private scheduled-job input outside durable Echo records."""
        return self._stage_memory_control_value(
            "_cron_mutation_payloads",
            owner_key_hash,
            payload,
            product_id=product_id,
            session_id=session_id,
        )

    def take_cron_mutation_payload(
        self,
        reference: str,
        owner_key_hash: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> dict[str, Any] | None:
        return self._take_memory_control_value(
            "_cron_mutation_payloads",
            reference,
            owner_key_hash,
            product_id=product_id,
            session_id=session_id,
        )

    def discard_cron_mutation_payload(
        self,
        reference: str,
        owner_key_hash: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> None:
        self._discard_memory_control_value(
            "_cron_mutation_payloads",
            reference,
            owner_key_hash,
            product_id=product_id,
            session_id=session_id,
        )

    def stage_cron_mutation_result(
        self,
        owner_key_hash: str,
        result: dict[str, Any],
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> str:
        """Stage a private cron response for one-time caller handoff."""
        return self._stage_memory_control_result(
            "_cron_mutation_results",
            owner_key_hash,
            result,
            product_id=product_id,
            session_id=session_id,
        )

    def take_cron_mutation_result(
        self,
        reference: str,
        owner_key_hash: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> dict[str, Any] | None:
        return self._take_memory_control_value(
            "_cron_mutation_results",
            reference,
            owner_key_hash,
            product_id=product_id,
            session_id=session_id,
        )
