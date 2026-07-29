"""Tool adapters for Work routines."""

from __future__ import annotations

import json
import re
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from js.tools.registry import ToolParam, ToolResult, ToolSpec
from js.utils.log import get_logger
from js_work.file_scope import (
    MaterializedSnapshotPath,
    WorkFileScopeError,
    WorkFileSnapshot,
    WorkOwnerFileScope,
    current_work_identity,
)
from js_work.routines.accessory_order import AccessoryOrderRoutineRunner
from js_work.routines.packing_details import PackingDetailsRoutineRunner
from js_work.routines.precise_edit import PreciseExcelEditEngine
from js_work.routines.spreadsheet import SpreadsheetTemplateEngine, WorkSpreadsheetRoutineRunner
from js_work.routines.store import WorkRoutineStore

logger = get_logger("js_work.routines.tools")

ROUTINE_TOOL_NAMES = {
    "accessory_order_run",
    "excel_template_analyze",
    "excel_extract_table",
    "excel_precise_edit",
    "excel_render_from_template",
    "excel_validate_output",
    "packing_details_run",
    "work_routine_preview",
    "work_routine_run",
    "control_work_routine_draft",
    "control_work_routine_approve",
}


class WorkRoutineTools:
    """Expose deterministic routine helpers to Work office profile."""

    def __init__(self, *, workspace: Path, state_dir: Path) -> None:
        self.workspace = workspace
        self.state_dir = state_dir
        self.engine = SpreadsheetTemplateEngine(workspace)

    def _store_for_current_owner(self) -> WorkRoutineStore:
        """Resolve the owner+session-partitioned store from the active Echo runtime context."""
        owner, session_id = current_work_identity()
        return WorkRoutineStore(
            self.state_dir,
            owner_key_hash=owner,
            session_id=session_id,
        )

    def _scope_for_current_owner(self) -> WorkOwnerFileScope:
        owner, session_id = current_work_identity()
        return WorkOwnerFileScope(
            self.workspace,
            owner=owner,
            session_id=session_id,
        )

    def _snapshot_input(
        self,
        stack: ExitStack,
        scope: WorkOwnerFileScope,
        path: str,
    ) -> MaterializedSnapshotPath | WorkFileSnapshot:
        snapshot = scope.read_routine_input(path)
        if snapshot.suffix == ".csv":
            return snapshot
        staged = stack.enter_context(scope.materialize_snapshot(snapshot))
        return staged

    def _output_path(self, path: str) -> str:
        scope = self._scope_for_current_owner()
        resolved = scope.resolve_output(path)
        return resolved.relative_to(scope.workspace).as_posix()

    def _public_payload(self, payload: Any) -> Any:
        return _public_work_value(payload, self._scope_for_current_owner())

    @staticmethod
    def _safe_failure(exc: Exception) -> ToolResult:
        """Return bounded public errors without exposing paths or workbook data."""
        if isinstance(exc, WorkFileScopeError):
            return ToolResult(
                success=False,
                error=exc.detail,
                metadata={"status_code": exc.status_code},
            )
        if isinstance(exc, KeyError):
            return ToolResult(success=False, error="Work routine not found")
        if isinstance(exc, json.JSONDecodeError):
            return ToolResult(success=False, error="Invalid Work routine JSON input")
        if isinstance(exc, PermissionError):
            return ToolResult(success=False, error="Work routine operation denied")
        logger.warning("Work routine operation failed: %s", type(exc).__name__)
        return ToolResult(success=False, error="Work routine operation failed safely")

    def get_specs(self) -> list[ToolSpec]:
        return [
            ToolSpec(
                name="accessory_order_run",
                description=(
                    "Calculate garment-accessory demand from quantity, style/BOM, and "
                    "accessory-master files, then create a supplier order workbook."
                ),
                parameters=[
                    ToolParam(
                        "quantity_path", "string", "Garment quantity file inside Work workspace"
                    ),
                    ToolParam("style_path", "string", "Style/BOM file inside Work workspace"),
                    ToolParam(
                        "accessory_path",
                        "string",
                        "Accessory supplier/master-data file inside Work workspace",
                    ),
                    ToolParam("output_path", "string", "Output supplier-order .xlsx path"),
                    ToolParam(
                        "color_aliases",
                        "string",
                        "Optional JSON object mapping garment-color aliases to canonical values",
                        required=False,
                    ),
                    ToolParam(
                        "unit_conversions",
                        "string",
                        "Optional JSON object mapping source->target units to positive factors",
                        required=False,
                    ),
                ],
                dangerous=True,
            ),
            ToolSpec(
                name="excel_precise_edit",
                description="Apply bounded, precise edits to a copied Excel workbook and write validation JSON.",
                parameters=[
                    ToolParam("source_path", "string", "Source .xlsx path inside Work workspace"),
                    ToolParam(
                        "output_path", "string", "New output .xlsx path inside Work workspace"
                    ),
                    ToolParam(
                        "operations",
                        "string",
                        (
                            "JSON array (max 256). Allowed op schemas: "
                            "set_cell/clear_cell use sheet+cell(+value); "
                            "copy_style uses sheet+source_cell+target_cell; "
                            "set_number_format uses sheet+cell+number_format; "
                            "set_row_height uses sheet+row+height; "
                            "set_column_width uses sheet+column+width; "
                            "merge_cells/unmerge_cells use sheet+range. "
                            "set_cell accepts scalar literals (formula-like strings stay "
                            'literals) or explicit {"__work_formula__":"=SUM(...)"} '
                            "for restricted Work formulas."
                        ),
                    ),
                    ToolParam(
                        "expected_source_sha256",
                        "string",
                        "Optional SHA-256 precondition for the source workbook",
                        required=False,
                    ),
                ],
                dangerous=True,
            ),
            ToolSpec(
                name="excel_template_analyze",
                description="Analyze an Excel template structure, headers, styles, merged cells, and formulas.",
                parameters=[
                    ToolParam("path", "string", "Template .xlsx path inside Work workspace")
                ],
                read_only=True,
            ),
            ToolSpec(
                name="excel_extract_table",
                description="Extract structured rows from an Excel source table using output-to-source field mapping.",
                parameters=[
                    ToolParam("path", "string", "Source .xlsx path inside Work workspace"),
                    ToolParam(
                        "mapping", "string", "JSON object mapping output fields to source headers"
                    ),
                ],
                read_only=True,
            ),
            ToolSpec(
                name="excel_render_from_template",
                description="Render rows into a new Excel file by copying a reference template's structure and styles.",
                parameters=[
                    ToolParam("template_path", "string", "Template .xlsx path"),
                    ToolParam("output_path", "string", "Output .xlsx path"),
                    ToolParam("rows", "string", "JSON array of row objects"),
                ],
                dangerous=True,
            ),
            ToolSpec(
                name="excel_validate_output",
                description="Validate generated Excel output and write an adjacent validation JSON report.",
                parameters=[
                    ToolParam("source_path", "string", "Source .xlsx path"),
                    ToolParam("template_path", "string", "Template .xlsx path"),
                    ToolParam("output_path", "string", "Output .xlsx path"),
                    ToolParam("rows", "string", "JSON array of row objects"),
                    ToolParam(
                        "required_fields",
                        "string",
                        "JSON array of required output fields",
                        required=False,
                    ),
                ],
                dangerous=True,
            ),
            ToolSpec(
                name="work_routine_preview",
                description="Preview an approved Work spreadsheet routine without writing output.",
                parameters=[
                    ToolParam("routine_id", "string", "Approved routine id"),
                    ToolParam("source_path", "string", "Source .xlsx path"),
                    ToolParam("template_path", "string", "Template .xlsx path", required=False),
                ],
                read_only=True,
            ),
            ToolSpec(
                name="work_routine_run",
                description="Run an approved Work spreadsheet routine and produce output plus validation report.",
                parameters=[
                    ToolParam("routine_id", "string", "Approved routine id"),
                    ToolParam("source_path", "string", "Source .xlsx path"),
                    ToolParam("template_path", "string", "Template .xlsx path", required=False),
                    ToolParam("output_path", "string", "Output .xlsx path"),
                ],
                dangerous=True,
            ),
            ToolSpec(
                name="packing_details_run",
                description="Run the Work PACKING DETAILS workflow for repeated two-column roll manifests.",
                parameters=[
                    ToolParam("source_path", "string", "Source .xlsx path inside Work workspace"),
                    ToolParam("template_path", "string", "Reference PACKING DETAILS .xlsx path"),
                    ToolParam("output_path", "string", "Output .xlsx path"),
                ],
                dangerous=True,
            ),
            ToolSpec(
                name="control_work_routine_draft",
                description="Internal administrator-approved Work routine draft creation.",
                parameters=[
                    ToolParam("name", "string", "Routine display name"),
                    ToolParam("trigger_phrases", "array", "Explicit routine trigger phrases"),
                    ToolParam(
                        "routine_type",
                        "string",
                        "Work routine type",
                        required=False,
                    ),
                    ToolParam(
                        "field_mapping",
                        "object",
                        "Output-to-source header mapping",
                        required=False,
                    ),
                    ToolParam("row_filters", "array", "Row filters", required=False),
                    ToolParam("header_aliases", "object", "Header aliases", required=False),
                    ToolParam(
                        "aggregation_rules",
                        "object",
                        "Aggregation rules",
                        required=False,
                    ),
                    ToolParam(
                        "validation_rules",
                        "object",
                        "Validation rules",
                        required=False,
                    ),
                    ToolParam("source_sheet", "string", "Source sheet", required=False),
                    ToolParam(
                        "review_policy",
                        "object",
                        "Review policy",
                        required=False,
                    ),
                    ToolParam("template_path", "string", "Template handle", required=False),
                ],
                model_visible=False,
            ),
            ToolSpec(
                name="control_work_routine_approve",
                description="Internal administrator-approved Work routine approval.",
                parameters=[ToolParam("routine_id", "string", "Work routine identifier")],
                model_visible=False,
            ),
        ]

    def register_all(self, registry: Any) -> None:
        for spec in self.get_specs():
            if spec.name == "accessory_order_run":
                registry.register(spec, self.accessory_order_run)
            elif spec.name == "excel_template_analyze":
                registry.register(spec, self.excel_template_analyze)
            elif spec.name == "excel_extract_table":
                registry.register(spec, self.excel_extract_table)
            elif spec.name == "excel_precise_edit":
                registry.register(spec, self.excel_precise_edit)
            elif spec.name == "excel_render_from_template":
                registry.register(spec, self.excel_render_from_template)
            elif spec.name == "excel_validate_output":
                registry.register(spec, self.excel_validate_output)
            elif spec.name == "work_routine_preview":
                registry.register(spec, self.work_routine_preview)
            elif spec.name == "work_routine_run":
                registry.register(spec, self.work_routine_run)
            elif spec.name == "packing_details_run":
                registry.register(spec, self.packing_details_run)
            elif spec.name == "control_work_routine_draft":
                registry.register(spec, self.control_work_routine_draft)
            elif spec.name == "control_work_routine_approve":
                registry.register(spec, self.control_work_routine_approve)

    @staticmethod
    def _bounded_control_payload(payload: dict[str, Any]) -> bool:
        try:
            encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError):
            return False
        return len(encoded) <= 256 * 1024

    async def control_work_routine_draft(
        self,
        name: str,
        trigger_phrases: list[str],
        routine_type: str = "spreadsheet_template",
        field_mapping: dict[str, str] | None = None,
        row_filters: list[dict[str, Any]] | None = None,
        header_aliases: dict[str, list[str]] | None = None,
        aggregation_rules: dict[str, Any] | None = None,
        validation_rules: dict[str, Any] | None = None,
        source_sheet: str = "",
        review_policy: dict[str, Any] | None = None,
        template_path: str = "",
    ) -> ToolResult:
        payload = {
            "name": name,
            "trigger_phrases": trigger_phrases,
            "routine_type": routine_type,
            "field_mapping": field_mapping or {},
            "row_filters": row_filters or [],
            "header_aliases": header_aliases or {},
            "aggregation_rules": aggregation_rules or {},
            "validation_rules": validation_rules or {},
            "source_sheet": source_sheet,
            "review_policy": review_policy or {},
            "template_path": template_path,
        }
        if (
            not isinstance(name, str)
            or not name.strip()
            or len(name) > 200
            or not isinstance(trigger_phrases, list)
            or not trigger_phrases
            or len(trigger_phrases) > 50
            or any(
                not isinstance(item, str) or not item.strip() or len(item) > 500
                for item in trigger_phrases
            )
            or not isinstance(routine_type, str)
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", routine_type)
            or not isinstance(field_mapping or {}, dict)
            or not isinstance(row_filters or [], list)
            or not all(isinstance(item, dict) for item in (row_filters or []))
            or not isinstance(header_aliases or {}, dict)
            or not isinstance(aggregation_rules or {}, dict)
            or not isinstance(validation_rules or {}, dict)
            or not isinstance(review_policy or {}, dict)
            or not isinstance(source_sheet, str)
            or len(source_sheet) > 500
            or not isinstance(template_path, str)
            or len(template_path) > 2048
            or not self._bounded_control_payload(payload)
        ):
            return ToolResult(
                success=False,
                error="Invalid Work routine draft",
                metadata={"status_code": 400},
            )
        try:
            routine = self._store_for_current_owner().create_draft(
                name=name.strip(),
                trigger_phrases=[item.strip() for item in trigger_phrases],
                routine_type=routine_type,
                field_mapping=dict(field_mapping or {}),
                row_filters=list(row_filters or []),
                header_aliases=dict(header_aliases or {}),
                aggregation_rules=dict(aggregation_rules or {}),
                validation_rules=dict(validation_rules or {}),
                source_sheet=source_sheet,
                review_policy=dict(review_policy or {}),
                template_path=template_path,
            )
        except (TypeError, ValueError):
            return ToolResult(
                success=False,
                error="Invalid Work routine draft",
                metadata={"status_code": 400},
            )
        except Exception:
            return ToolResult(
                success=False,
                error="Work routine draft could not be stored safely",
                metadata={"status_code": 500},
            )
        result = routine.to_dict()
        return ToolResult(
            success=True,
            output=json.dumps(result, ensure_ascii=False),
            metadata={"routine": result},
        )

    async def control_work_routine_approve(self, routine_id: str) -> ToolResult:
        try:
            routine = self._store_for_current_owner().approve(routine_id)
        except KeyError:
            return ToolResult(
                success=False,
                error="Work routine was not found",
                metadata={"status_code": 404},
            )
        except (TypeError, ValueError):
            return ToolResult(
                success=False,
                error="Invalid Work routine identifier",
                metadata={"status_code": 400},
            )
        except Exception:
            return ToolResult(
                success=False,
                error="Work routine approval could not be stored safely",
                metadata={"status_code": 500},
            )
        result = routine.to_dict()
        return ToolResult(
            success=True,
            output=json.dumps(result, ensure_ascii=False),
            metadata={"routine": result},
        )

    async def accessory_order_run(
        self,
        quantity_path: str,
        style_path: str,
        accessory_path: str,
        output_path: str,
        color_aliases: str = "{}",
        unit_conversions: str = "{}",
    ) -> ToolResult:
        try:
            parsed_color_aliases = json.loads(color_aliases)
            parsed_unit_conversions = json.loads(unit_conversions)
            if not isinstance(parsed_color_aliases, dict) or not isinstance(
                parsed_unit_conversions, dict
            ):
                raise ValueError("Accessory rules must be JSON objects")
            scope = self._scope_for_current_owner()
            with ExitStack() as stack:
                result = AccessoryOrderRoutineRunner(
                    self.workspace,
                    allowed_roots=(scope.private_root, scope.owned_upload_root),
                ).run(
                    quantity_path=self._snapshot_input(stack, scope, quantity_path),
                    style_path=self._snapshot_input(stack, scope, style_path),
                    accessory_path=self._snapshot_input(stack, scope, accessory_path),
                    output_path=self._output_path(output_path),
                    color_aliases=parsed_color_aliases,
                    unit_conversions=parsed_unit_conversions,
                )
            payload = result.to_dict()
            try:
                report = json.loads(Path(result.report_path).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                report = None
            payload["report"] = report
            if report is None:
                payload["report_status"] = "unavailable"
            if result.status != "passed":
                payload["warning"] = (
                    f"status={result.status}: 存在 {result.issue_count} 个待审核问题，"
                    "输出不得直接作为供应商正式订单"
                )
            public_payload = self._public_payload(payload)
            return ToolResult(
                success=True,
                output=json.dumps(public_payload, ensure_ascii=False, indent=2),
                metadata={
                    "status": result.status,
                    "output_path": public_payload["output_path"],
                    "report_path": public_payload["report_path"],
                    "report": public_payload["report"],
                },
            )
        except Exception as exc:
            return self._safe_failure(exc)

    async def excel_template_analyze(self, path: str) -> ToolResult:
        try:
            scope = self._scope_for_current_owner()
            with ExitStack() as stack:
                template = self._snapshot_input(stack, scope, path)
                if isinstance(template, WorkFileSnapshot):
                    raise ValueError("spreadsheet templates must be .xlsx files")
                analysis = self.engine.analyze_template(template)
            return ToolResult(
                success=True,
                output=json.dumps(analysis.to_dict(), ensure_ascii=False, indent=2),
                metadata={"template_hash": analysis.template_hash},
            )
        except Exception as exc:
            return self._safe_failure(exc)

    async def excel_extract_table(self, path: str, mapping: str) -> ToolResult:
        try:
            scope = self._scope_for_current_owner()
            with ExitStack() as stack:
                rows = self.engine.extract_rows(
                    self._snapshot_input(stack, scope, path),
                    field_mapping=json.loads(mapping),
                )
            return ToolResult(
                success=True,
                output=json.dumps(rows, ensure_ascii=False, indent=2),
                metadata={"rows": len(rows)},
            )
        except Exception as exc:
            return self._safe_failure(exc)

    async def excel_precise_edit(
        self,
        source_path: str,
        output_path: str,
        operations: str,
        expected_source_sha256: str = "",
    ) -> ToolResult:
        try:
            scope = self._scope_for_current_owner()
            with ExitStack() as stack:
                staged_source = self._snapshot_input(stack, scope, source_path)
                if isinstance(staged_source, WorkFileSnapshot):
                    raise ValueError("precise edits require an .xlsx source")
                report = PreciseExcelEditEngine(self.workspace).apply(
                    source_path=staged_source,
                    output_path=self._output_path(output_path),
                    operations=json.loads(operations),
                    expected_source_sha256=expected_source_sha256 or None,
                )
            public_report = self._public_payload(report)
            return ToolResult(
                success=True,
                output=json.dumps(public_report, ensure_ascii=False, indent=2),
                metadata={
                    "status": public_report["status"],
                    "output_path": public_report["output_path"],
                    "validation_path": public_report["validation_path"],
                },
            )
        except Exception as exc:
            return self._safe_failure(exc)

    async def excel_render_from_template(
        self,
        template_path: str,
        output_path: str,
        rows: str,
    ) -> ToolResult:
        try:
            parsed_rows = json.loads(rows)
            scope = self._scope_for_current_owner()
            with ExitStack() as stack:
                staged_template = self._snapshot_input(stack, scope, template_path)
                if isinstance(staged_template, WorkFileSnapshot):
                    raise ValueError("spreadsheet templates must be .xlsx files")
                output = self.engine.render_from_template(
                    template_path=staged_template,
                    output_path=self._output_path(output_path),
                    rows=parsed_rows,
                )
            public_path = self._scope_for_current_owner().to_public_handle(output)
            return ToolResult(success=True, output=public_path, metadata={"path": public_path})
        except Exception as exc:
            return self._safe_failure(exc)

    async def excel_validate_output(
        self,
        source_path: str,
        template_path: str,
        output_path: str,
        rows: str,
        required_fields: str = "[]",
    ) -> ToolResult:
        try:
            scope = self._scope_for_current_owner()
            with ExitStack() as stack:
                source = self._snapshot_input(stack, scope, source_path)
                template = self._snapshot_input(stack, scope, template_path)
                if isinstance(template, WorkFileSnapshot):
                    raise ValueError("spreadsheet templates must be .xlsx files")
                report = self.engine.validate_output(
                    source_path=source,
                    template_path=template,
                    output_path=self._output_path(output_path),
                    rows=json.loads(rows),
                    required_fields=json.loads(required_fields or "[]"),
                )
            return ToolResult(
                success=True,
                output=json.dumps(report, ensure_ascii=False, indent=2),
                metadata={"status": report["status"]},
            )
        except Exception as exc:
            return self._safe_failure(exc)

    async def work_routine_preview(
        self,
        routine_id: str,
        source_path: str,
        template_path: str = "",
    ) -> ToolResult:
        try:
            store = self._store_for_current_owner()
            routine = store.get(routine_id)
            if routine.routine_type == "packing_details":
                return ToolResult(
                    success=False,
                    error="dry_run is not supported for packing_details routines",
                )
            scope = self._scope_for_current_owner()
            with ExitStack() as stack:
                source = self._snapshot_input(stack, scope, source_path)
                template = self._snapshot_input(
                    stack,
                    scope,
                    template_path or routine.template_path,
                )
                if isinstance(template, WorkFileSnapshot):
                    raise ValueError("spreadsheet templates must be .xlsx files")
                preview = WorkSpreadsheetRoutineRunner(
                    self.workspace,
                    self.state_dir,
                ).preview(
                    routine=routine,
                    source_path=source,
                    template_path=template,
                )
            return ToolResult(
                success=True,
                output=json.dumps(preview, ensure_ascii=False, indent=2),
                metadata={
                    "status": preview.get("status"),
                    "dry_run": True,
                    "report": preview,
                },
            )
        except Exception as exc:
            return self._safe_failure(exc)

    async def work_routine_run(
        self,
        routine_id: str,
        source_path: str,
        template_path: str = "",
        output_path: str = "",
    ) -> ToolResult:
        try:
            if not output_path:
                return ToolResult(success=False, error="output_path is required")
            store = self._store_for_current_owner()
            routine = store.get(routine_id)
            effective_template = template_path or routine.template_path
            scope = self._scope_for_current_owner()
            if routine.routine_type == "packing_details":
                with ExitStack() as stack:
                    source = self._snapshot_input(stack, scope, source_path)
                    template = self._snapshot_input(stack, scope, effective_template)
                    if isinstance(source, WorkFileSnapshot) or isinstance(
                        template,
                        WorkFileSnapshot,
                    ):
                        raise ValueError("packing details inputs must be Excel files")
                    packing_result = PackingDetailsRoutineRunner(self.workspace).run(
                        source_path=source,
                        template_path=template,
                        output_path=self._output_path(output_path),
                    )
                payload = packing_result.to_dict()
                try:
                    payload["report"] = json.loads(
                        Path(packing_result.report_path).read_text(encoding="utf-8")
                    )
                except (OSError, ValueError):
                    payload["report"] = None
                public_payload = self._public_payload(payload)
                return ToolResult(
                    success=True,
                    output=json.dumps(public_payload, ensure_ascii=False, indent=2),
                    metadata={
                        "status": packing_result.status,
                        "output_path": public_payload["output_path"],
                        "report_path": public_payload["report_path"],
                        "report": public_payload["report"],
                    },
                )
            with ExitStack() as stack:
                source = self._snapshot_input(stack, scope, source_path)
                template = self._snapshot_input(stack, scope, effective_template)
                if isinstance(template, WorkFileSnapshot):
                    raise ValueError("spreadsheet templates must be .xlsx files")
                spreadsheet_result = WorkSpreadsheetRoutineRunner(
                    self.workspace,
                    self.state_dir,
                ).run(
                    routine=routine,
                    source_path=source,
                    template_path=template,
                    output_path=self._output_path(output_path),
                )
            payload = spreadsheet_result.to_dict()
            try:
                report = json.loads(
                    Path(spreadsheet_result.report_path).read_text(encoding="utf-8")
                )
            except Exception:
                report = None
            payload["report"] = report
            public_payload = self._public_payload(payload)
            return ToolResult(
                success=True,
                output=json.dumps(public_payload, ensure_ascii=False, indent=2),
                metadata={
                    "status": spreadsheet_result.status,
                    "report_path": public_payload["report_path"],
                    "report": public_payload["report"],
                },
            )
        except Exception as exc:
            return self._safe_failure(exc)

    async def packing_details_run(
        self,
        source_path: str,
        template_path: str,
        output_path: str,
    ) -> ToolResult:
        try:
            scope = self._scope_for_current_owner()
            with ExitStack() as stack:
                source = self._snapshot_input(stack, scope, source_path)
                template = self._snapshot_input(stack, scope, template_path)
                if isinstance(source, WorkFileSnapshot) or isinstance(
                    template,
                    WorkFileSnapshot,
                ):
                    raise ValueError("packing details inputs must be Excel files")
                result = PackingDetailsRoutineRunner(self.workspace).run(
                    source_path=source,
                    template_path=template,
                    output_path=self._output_path(output_path),
                )
            payload = result.to_dict()
            try:
                payload["report"] = json.loads(Path(result.report_path).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                payload["report"] = None
            public_result = self._public_payload(payload)
            return ToolResult(
                success=True,
                output=json.dumps(public_result, ensure_ascii=False, indent=2),
                metadata={
                    "status": result.status,
                    "output_path": public_result["output_path"],
                    "report_path": public_result["report_path"],
                    "report": public_result["report"],
                },
            )
        except Exception as exc:
            return self._safe_failure(exc)


_PUBLIC_PATH_KEYS = {
    "output_path",
    "path",
    "report_path",
    "source_path",
    "validation_path",
}


def _public_work_value(value: Any, scope: WorkOwnerFileScope, *, key: str = "") -> Any:
    if isinstance(value, dict):
        return {
            item_key: _public_work_value(item, scope, key=str(item_key))
            for item_key, item in value.items()
        }
    if isinstance(value, list):
        return [_public_work_value(item, scope) for item in value]
    if key in _PUBLIC_PATH_KEYS and isinstance(value, str):
        return scope.to_public_handle(value)
    return value
