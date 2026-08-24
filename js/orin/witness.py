"""AppShell owner-witness identity and default intent templates (K5).

The private Ed25519 witness key lives under
``<state_dir>/orin/appshell_witness/`` and is loaded ONLY by AppShell code
paths — the Echo turn loop has no reason to ever touch it. orind verifies
intents against the published public key at ``<state_dir>/orin/witness.pub``
(a copy, not a secret). A model-controlled process can therefore carry an
already-signed envelope around, but any single-byte tampering breaks the
signature: Echo cannot mint owner authority.

Templates implement the ratified defaults (M decision on D7 / task §WP8):
- personal: read + stage + exact email egress; no standing sink grant;
- work:     read + stage + exact email egress to pre-registered sinks;
- factory:  narrow fixed-recipient template with dual control (placeholder).
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from js.orin.intent import Budgets, IntentEnvelope, request_hash_of
from js.security.signer import (
    generate_signing_key,
    get_public_key,
    load_signing_key,
)

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric import ed25519

WITNESS_KEY_DIRNAME: Final[str] = "appshell_witness"
WITNESS_PUB_FILENAME: Final[str] = "witness.pub"

DEFAULT_TEMPLATES: Final[dict[str, dict[str, Any]]] = {
    "personal": {
        "classes": (
            "artifact.read",
            "artifact.stage",
            "net.fetch",
            "email.send_exact",
            "file.commit",
        ),
        "policy": "exact_commit_required",
    },
    "work": {
        "classes": (
            "artifact.read",
            "artifact.stage",
            "net.fetch",
            "shell.exec",
            "email.send_exact",
            "file.commit",
        ),
        "policy": "preauthorized_exact_template",
    },
    # Factory stays a configurable placeholder until a real deployment
    # defines its fixed recipient sets (task §WP5).
    "factory": {
        "classes": ("artifact.read", "artifact.stage", "net.fetch", "email.send_exact"),
        "policy": "dual_control",
    },
}


def _witness_dir(state_dir: Path) -> Path:
    return state_dir / "orin" / WITNESS_KEY_DIRNAME


def ensure_witness_keypair(state_dir: Path) -> tuple[ed25519.Ed25519PrivateKey, str]:
    """Load or create the AppShell signing identity; publish the public half.

    Returns ``(private_key, public_key_b64)``. The published copy at
    ``<state_dir>/orin/witness.pub`` is what orind registers — it contains
    no secret material.
    """

    directory = _witness_dir(state_dir)
    directory.mkdir(parents=True, exist_ok=True)
    private_key = load_signing_key(directory)
    if private_key is None:
        private_key = generate_signing_key(directory)
    public_b64 = get_public_key(directory)
    pub_path = state_dir / "orin" / WITNESS_PUB_FILENAME
    tmp_path = pub_path.with_suffix(".pub.tmp")
    tmp_path.write_text(public_b64 + "\n", encoding="utf-8")
    tmp_path.chmod(0o644)
    tmp_path.replace(pub_path)
    return private_key, public_b64


def load_published_public_key(state_dir: Path) -> str | None:
    """Read the published witness pubkey (orind side); None when absent."""

    pub_path = state_dir / "orin" / WITNESS_PUB_FILENAME
    try:
        text = pub_path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return text or None


def build_intent_from_template(
    *,
    template: str,
    task_id: str,
    raw_request: str,
    owner_key_hash: str,
    product_id: str = "js-agent",
    ttl_ms: int = 60 * 60 * 1000,
    now_ms: int | None = None,
    sink_handles: tuple[str, ...] = (),
    resource_handles: tuple[str, ...] = ("dirh:workspace",),
) -> IntentEnvelope:
    """Instantiate one of ``DEFAULT_TEMPLATES`` as an unsigned envelope."""

    spec = DEFAULT_TEMPLATES.get(template)
    if spec is None:
        raise ValueError(f"unknown intent template {template!r}")
    ts = int(time.time() * 1000) if now_ms is None else now_ms
    classes = tuple(spec["classes"])
    if template == "personal" and sink_handles:
        raise ValueError("personal template grants no standing sinks")
    return IntentEnvelope(
        intent_id=f"intent:{ts:x}-{task_id[-12:]}",
        owner_key_hash=owner_key_hash,
        product_id=product_id,
        profile=template,
        task_id=task_id,
        raw_request_hash=request_hash_of(raw_request),
        allowed_effect_classes=classes,
        allowed_resource_handles=resource_handles,
        allowed_sink_handles=tuple(sink_handles),
        budgets=Budgets(
            max_invocations=200,
            max_bytes_read=1 << 30,
            # Personal has no standing sink, but a separately granted exact
            # ExportPass still needs a finite, non-zero byte budget.
            max_bytes_out=1 << 20,
            max_cost_minor_units=0,
        ),
        approval_policy=str(spec["policy"]),
        issued_by="appshell:owner-witness",
        issued_at_ms=ts - 1000,
        expires_at_ms=ts + ttl_ms,
    )


__all__ = [
    "DEFAULT_TEMPLATES",
    "WITNESS_PUB_FILENAME",
    "build_intent_from_template",
    "ensure_witness_keypair",
    "load_published_public_key",
]
