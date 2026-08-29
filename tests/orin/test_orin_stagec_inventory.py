"""C0 enforce inventory is pinned; unknown names fail closed."""

from __future__ import annotations

import pytest

from js.orin.inventory import (
    PINNED_INVENTORY_DIGEST,
    file_cell_mapped_tool,
    inventory_digest,
    inventory_digest_matches,
    mcp_or_webbridge_disabled,
    require_no_unclassified_exits,
    should_register_product_tool,
    unclassified_registered_tools,
)


def test_inventory_digest_is_pinned() -> None:
    assert inventory_digest() == PINNED_INVENTORY_DIGEST
    assert inventory_digest_matches() is True


def test_unclassified_names_fail_closed() -> None:
    assert unclassified_registered_tools(("file_read", "excel_write")) == ()
    assert unclassified_registered_tools(("mystery_tool",)) == ("mystery_tool",)
    with pytest.raises(RuntimeError, match="unclassified enforce exits"):
        require_no_unclassified_exits(("file_read", "mystery_tool"))


def test_disabled_in_enforce_names_are_classified() -> None:
    assert should_register_product_tool("excel_write", enforce=True) is False
    assert should_register_product_tool("csv_read", enforce=True) is True
    assert should_register_product_tool("file_read", enforce=True) is True
    assert file_cell_mapped_tool("excel_write") is True
    assert file_cell_mapped_tool("pdf_generate") is True
    assert mcp_or_webbridge_disabled("mcp_call") is True
    assert mcp_or_webbridge_disabled("browser_open") is True
    assert mcp_or_webbridge_disabled("file_read") is False
