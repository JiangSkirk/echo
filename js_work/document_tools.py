"""Owner-scoped Work tool adapters for PDF and Word documents."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from js.tools.registry import ToolParam, ToolResult, ToolSpec
from js.utils.log import get_logger
from js_work.documents import WorkDocumentEngine
from js_work.file_scope import WorkOwnerFileScope, current_work_identity

DOCUMENT_TOOL_NAMES = {"pdf_extract", "word_read", "word_create", "word_replace"}
logger = get_logger("js_work.document_tools")


class WorkDocumentTools:
    """Expose bounded document operations inside the active Work owner scope."""

    def __init__(self, *, workspace: Path) -> None:
        self.workspace = workspace

    def _scope(self) -> WorkOwnerFileScope:
        owner, session_id = current_work_identity()
        return WorkOwnerFileScope(
            self.workspace,
            owner=owner,
            session_id=session_id,
        )

    def _input_snapshot(self, path: str) -> Any:
        return self._scope().read_routine_input(path)

    def _output_path(self, path: str) -> str:
        scope = self._scope()
        return scope.resolve_output(path).relative_to(scope.workspace).as_posix()

    def get_specs(self) -> list[ToolSpec]:
        return [
            ToolSpec(
                name="pdf_extract",
                description="Extract bounded page text and metadata from a PDF in the Work workspace.",
                parameters=[ToolParam("path", "string", "Input .pdf path")],
                read_only=True,
            ),
            ToolSpec(
                name="word_read",
                description="Read paragraphs and tables from a safe .docx file.",
                parameters=[ToolParam("path", "string", "Input .docx path")],
                read_only=True,
            ),
            ToolSpec(
                name="word_create",
                description="Create an audited Word document from structured sections.",
                parameters=[
                    ToolParam("output_path", "string", "Output .docx path"),
                    ToolParam("title", "string", "Document title"),
                    ToolParam(
                        "sections",
                        "string",
                        "JSON section array with heading, paragraphs, bullets, and optional table",
                    ),
                ],
                dangerous=True,
            ),
            ToolSpec(
                name="word_replace",
                description="Create a new audited .docx by replacing text without overwriting the source.",
                parameters=[
                    ToolParam("source_path", "string", "Input .docx path"),
                    ToolParam("output_path", "string", "New output .docx path"),
                    ToolParam("replacements", "string", "JSON object mapping old text to new text"),
                ],
                dangerous=True,
            ),
        ]

    def register_all(self, registry: Any) -> None:
        handlers = {
            "pdf_extract": self.pdf_extract,
            "word_read": self.word_read,
            "word_create": self.word_create,
            "word_replace": self.word_replace,
        }
        for spec in self.get_specs():
            registry.register(spec, handlers[spec.name])

    async def pdf_extract(self, path: str) -> ToolResult:
        return self._read(lambda engine: engine.read_pdf(self._input_snapshot(path)))

    async def word_read(self, path: str) -> ToolResult:
        return self._read(lambda engine: engine.read_word(self._input_snapshot(path)))

    async def word_create(self, output_path: str, title: str, sections: str) -> ToolResult:
        try:
            parsed = json.loads(sections)
        except (TypeError, json.JSONDecodeError):
            return ToolResult(success=False, error="Invalid Word sections JSON")
        if not isinstance(parsed, list):
            return ToolResult(success=False, error="Invalid Word sections JSON")
        try:
            result = WorkDocumentEngine(self.workspace).create_word(
                output_path=self._output_path(output_path),
                title=title,
                sections=parsed,
            )
            return _success(result, self._scope())
        except Exception as exc:
            logger.warning(
                "Word document creation failed: %s",
                type(exc).__name__,
            )
            return ToolResult(
                success=False,
                error="Word document creation failed safely",
            )

    async def word_replace(
        self,
        source_path: str,
        output_path: str,
        replacements: str,
    ) -> ToolResult:
        try:
            parsed = json.loads(replacements)
        except (TypeError, json.JSONDecodeError):
            return ToolResult(success=False, error="Invalid Word replacements JSON")
        if not isinstance(parsed, dict):
            return ToolResult(success=False, error="Invalid Word replacements JSON")
        try:
            result = WorkDocumentEngine(self.workspace).replace_word(
                source_path=self._input_snapshot(source_path),
                output_path=self._output_path(output_path),
                replacements=parsed,
            )
            return _success(result, self._scope())
        except Exception as exc:
            logger.warning(
                "Word document replacement failed: %s",
                type(exc).__name__,
            )
            return ToolResult(
                success=False,
                error="Word document replacement failed safely",
            )

    def _read(self, operation: Any) -> ToolResult:
        try:
            return _success(operation(WorkDocumentEngine(self.workspace)), self._scope())
        except Exception as exc:
            logger.warning("Document read failed: %s", type(exc).__name__)
            return ToolResult(success=False, error="Document read failed safely")


def _success(payload: dict[str, Any], scope: WorkOwnerFileScope) -> ToolResult:
    public_payload = _public_payload(payload, scope)
    return ToolResult(
        success=True,
        output=json.dumps(public_payload, ensure_ascii=False, indent=2),
        metadata={
            key: public_payload[key]
            for key in ("status", "output_path", "report_path", "page_count")
            if key in public_payload
        },
    )


def _public_payload(payload: dict[str, Any], scope: WorkOwnerFileScope) -> dict[str, Any]:
    path_keys = {"path", "output_path", "report_path", "source_path"}
    return {
        key: scope.to_public_handle(value)
        if key in path_keys and isinstance(value, str)
        else value
        for key, value in payload.items()
    }
