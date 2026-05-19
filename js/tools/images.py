"""Image encoding tools for vision-capable LLMs.

Converts image files to base64 data URLs for OpenAI-compatible
multimodal message formats.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

SUPPORTED_IMAGE_SUFFIXES = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}
MAX_IMAGE_SIZE = 20 * 1024 * 1024  # 20 MB


def is_image(path: Path) -> bool:
    return path.suffix.lower() in SUPPORTED_IMAGE_SUFFIXES


def encode_to_base64(path: Path) -> str:
    """Encode an image file to a base64 data URL."""
    data = path.read_bytes()
    b64 = base64.b64encode(data).decode("ascii")
    mime = _guess_mime(path.suffix)
    return f"data:{mime};base64,{b64}"


def create_image_message(path: Path) -> dict[str, Any]:
    """Create an OpenAI-style image_url message part."""
    return {
        "type": "image_url",
        "image_url": {"url": encode_to_base64(path)},
    }


def _guess_mime(suffix: str) -> str:
    mapping = {
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".gif": "image/gif",
        ".webp": "image/webp",
        ".bmp": "image/bmp",
    }
    return mapping.get(suffix.lower(), "image/png")
