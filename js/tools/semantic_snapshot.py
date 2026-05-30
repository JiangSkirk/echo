"""Semantic Snapshot: accessibility-tree browser navigation (OpenClaw-style).

Instead of sending screenshots (~5MB, expensive in tokens), we parse the
page's accessibility tree into a compact text representation. Each
interactive element gets a numbered ``ref`` ID. The agent says
"click ref=3" which maps to exactly one DOM element.

This cuts browsing token costs by ~90% vs screenshot-based navigation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from js.utils.log import get_logger

logger = get_logger("js.tools.semantic_snapshot")


@dataclass
class SemanticElement:
    """A single interactive element in the semantic snapshot."""

    ref: int
    tag: str
    role: str
    name: str
    text: str
    attrs: dict[str, str]


class SemanticSnapshot:
    """Build and interact with semantic page snapshots."""

    def __init__(self, snapshot_data: dict[str, Any] | None = None) -> None:
        self.elements: list[SemanticElement] = []
        self.title: str = ""
        self.url: str = ""
        if snapshot_data:
            self._parse(snapshot_data)

    def _parse(self, data: dict[str, Any]) -> None:
        self.title = data.get("title", "")
        self.url = data.get("url", "")
        ref = 0
        for node in data.get("nodes", []):
            parsed = self._parse_node(node, ref)
            if parsed:
                self.elements.append(parsed)
                ref += 1

    def _parse_node(self, node: dict[str, Any], ref: int) -> SemanticElement | None:
        """Parse a single accessibility node."""
        role = node.get("role", "")
        name = node.get("name", "")
        text = node.get("text", "")
        if not role and not name and not text:
            return None
        # Only keep interactive or informative nodes
        interactive_roles = {
            "button", "link", "textbox", "checkbox", "radio", "combobox",
            "menuitem", "tab", "treeitem", "slider", "spinbutton", "switch",
            "searchbox", "heading", "paragraph", "listitem", "table",
        }
        if role not in interactive_roles and not name:
            return None
        return SemanticElement(
            ref=ref,
            tag=node.get("tag", ""),
            role=role,
            name=name,
            text=text[:200],
            attrs={k: str(v) for k, v in node.get("attributes", {}).items()},
        )

    def to_text(self, max_length: int = 8000) -> str:
        """Render snapshot as compact text for LLM consumption."""
        lines: list[str] = []
        if self.title:
            lines.append(f"# {self.title}")
        if self.url:
            lines.append(f"URL: {self.url}")
        lines.append("")
        for el in self.elements:
            if el.role == "heading":
                lines.append(f"## {el.name or el.text}")
            elif el.role == "paragraph":
                lines.append(el.text)
            else:
                attr_str = ""
                if el.attrs.get("href"):
                    attr_str = f" href={el.attrs['href'][:80]}"
                lines.append(
                    f"- [{el.ref}] {el.role}: {el.name or el.text}{attr_str}"
                )
        text = "\n".join(lines)
        if len(text) > max_length:
            text = text[:max_length] + "\n... [truncated]"
        return text

    def find_by_ref(self, ref: int) -> SemanticElement | None:
        """Lookup element by its ref number."""
        for el in self.elements:
            if el.ref == ref:
                return el
        return None

    def find_by_text(self, query: str) -> list[SemanticElement]:
        """Find elements matching a text query."""
        q = query.lower()
        return [el for el in self.elements if q in (el.name or "").lower() or q in (el.text or "").lower()]

    @classmethod
    def from_playwright_page(cls, page: Any) -> SemanticSnapshot:
        """Build a snapshot from a Playwright page object."""
        try:
            # Playwright accessibility snapshot
            snapshot = page.accessibility.snapshot()
            return cls({
                "title": page.title(),
                "url": page.url,
                "nodes": _flatten_ax_tree(snapshot),
            })
        except Exception as e:
            logger.warning(f"Accessibility snapshot failed: {e}")
            # Fallback: extract text content
            try:
                text = page.evaluate("() => document.body.innerText")
                return cls({
                    "title": page.title(),
                    "url": page.url,
                    "nodes": [{"role": "paragraph", "text": text[:4000]}],
                })
            except Exception:
                return cls()


def _flatten_ax_tree(tree: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten Playwright accessibility tree into a list of nodes."""
    nodes: list[dict[str, Any]] = []

    def _walk(node: dict[str, Any]) -> None:
        role = node.get("role", "")
        name = node.get("name", "")
        if role or name:
            nodes.append({
                "role": role,
                "name": name,
                "text": node.get("value", ""),
                "tag": "",
                "attributes": {},
            })
        for child in node.get("children", []):
            _walk(child)

    _walk(tree)
    return nodes


# ---------------------------------------------------------------------------
# Action helpers
# ---------------------------------------------------------------------------

@dataclass
class SnapshotAction:
    """A structured action on a semantic snapshot."""

    action: str  # click, fill, scroll, navigate
    ref: int | None = None
    value: str = ""
    url: str = ""

    def to_playwright(self, page: Any, snapshot: SemanticSnapshot) -> dict[str, Any]:
        """Convert to Playwright executable instruction."""
        if self.action == "navigate":
            return {"action": "goto", "url": self.url}
        el = snapshot.find_by_ref(self.ref) if self.ref is not None else None
        if not el:
            return {"action": "error", "message": f"Ref {self.ref} not found"}
        if self.action == "click":
            # Use ref-based selector if available, fallback to text
            selector = f"[data-js-ref='{self.ref}']"
            return {"action": "click", "selector": selector, "fallback_text": el.name or el.text}
        if self.action == "fill":
            selector = f"[data-js-ref='{self.ref}']"
            return {"action": "fill", "selector": selector, "value": self.value}
        if self.action == "scroll":
            return {"action": "scroll", "direction": self.value or "down"}
        return {"action": "error", "message": f"Unknown action {self.action}"}


def parse_agent_action(text: str) -> SnapshotAction | None:
    """Parse an agent's natural-language action into a structured SnapshotAction.

    Supported formats:
      - "click ref=3"
      - "fill ref=5 with hello world"
      - "navigate to https://example.com"
      - "scroll down"
    """
    text = text.strip().lower()
    if text.startswith("navigate to ") or text.startswith("goto "):
        url = text.split(" ", 2)[-1].strip()
        return SnapshotAction(action="navigate", url=url)
    if text.startswith("scroll "):
        direction = text.split(" ", 1)[-1].strip()
        return SnapshotAction(action="scroll", value=direction)

    import re
    # click ref=3
    m = re.match(r"click\s+ref[=:]?\s*(\d+)", text)
    if m:
        return SnapshotAction(action="click", ref=int(m.group(1)))
    # fill ref=5 with hello
    m = re.match(r"fill\s+ref[=:]?\s*(\d+)\s+with\s+(.+)", text)
    if m:
        return SnapshotAction(action="fill", ref=int(m.group(1)), value=m.group(2).strip())
    # fill ref=5: hello
    m = re.match(r"fill\s+ref[=:]?\s*(\d+)[:\s]+(.+)", text)
    if m:
        return SnapshotAction(action="fill", ref=int(m.group(1)), value=m.group(2).strip())

    return None
