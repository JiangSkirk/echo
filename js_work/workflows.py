"""Small built-in Work intent router.

These workflows are product behavior, not JS Agent skills. They only shape the
prompt sent to the Echo-backed core agent and rely on the active Work profile.
"""

from __future__ import annotations

from enum import StrEnum


class WorkIntent(StrEnum):
    GENERAL = "general"
    RESEARCH = "research"
    PROJECT_BREAKDOWN = "project_breakdown"
    SPREADSHEET_ROUTINE = "spreadsheet_routine"


class WorkIntentRouter:
    """Classify common Work tasks and add narrow execution guidance."""

    def classify(self, message: str) -> WorkIntent:
        text = message.lower()
        research_markers = ("搜索", "调研", "研究", "资料", "行业报告", "research", "search")
        project_markers = ("拆解", "拆成", "任务", "计划", "项目", "里程碑", "breakdown", "plan")
        spreadsheet_markers = (
            "表格1",
            "表格2",
            "表格3",
            "表格",
            "模板",
            "面料统计",
            "统计表",
            "工作簿",
            "excel",
            ".xlsx",
            ".csv",
        )
        if any(marker in text for marker in spreadsheet_markers):
            return WorkIntent.SPREADSHEET_ROUTINE
        if any(marker in text for marker in research_markers):
            return WorkIntent.RESEARCH
        if any(marker in text for marker in project_markers):
            return WorkIntent.PROJECT_BREAKDOWN
        return WorkIntent.GENERAL

    def prepare_message(self, message: str) -> str:
        intent = self.classify(message)
        if intent == WorkIntent.RESEARCH:
            guidance = (
                "工作模式：资料调研。优先使用搜索和网页读取来确认事实，"
                "整理来源、结论和不确定点。不要调用 skill，也不要假装已经验证未搜索的信息。"
            )
        elif intent == WorkIntent.PROJECT_BREAKDOWN:
            guidance = (
                "工作模式：项目拆解。先把目标拆成可执行任务，再标明依赖、风险和验收标准。"
                "复杂并行工作可以使用 agent 集群。不要调用 skill。"
            )
        elif intent == WorkIntent.SPREADSHEET_ROUTINE:
            guidance = (
                "工作模式：表格 Routine。优先匹配已启用的 Work Routine；没有匹配时先分析来源表"
                "和参考模板，生成可审核的字段映射、抽取规则和校验规则。输出文件必须按模板结构"
                "和样式生成，并经过规则校验与独立 reviewer 复核后才算完成。不要调用 skill。"
            )
        else:
            guidance = (
                "工作模式：普通执行。按当前工具权限完成任务；需要事实时先搜索，"
                "需要改文件时只在 Work 工作区内操作。不要调用 skill。"
            )
        return f"{guidance}\n\n用户任务：{message}"
