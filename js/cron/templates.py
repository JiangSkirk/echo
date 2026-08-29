"""Built-in task templates for common scheduled operations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class TaskTemplate:
    """A pre-defined task template that users can instantiate."""

    id: str
    name: str
    description: str
    task_type: str
    default_cron: str
    default_payload: dict[str, Any]
    icon: str = "⏰"
    category: str = "general"


TEMPLATE_REGISTRY: dict[str, TaskTemplate] = {
    t.id: t
    for t in [
        # Health & Maintenance
        TaskTemplate(
            id="health_check",
            name="系统健康检查",
            description="检查模型提供商状态、内存使用、磁盘空间等系统指标",
            task_type="health_check",
            default_cron="0 */6 * * *",
            default_payload={"providers": True, "memory": True, "disk": True},
            icon="🏥",
            category="maintenance",
        ),
        TaskTemplate(
            id="session_cleanup",
            name="清理空会话",
            description="删除没有消息的空白会话，释放存储空间",
            task_type="cleanup",
            default_cron="0 3 * * *",
            default_payload={"older_than_days": 7, "dry_run": False},
            icon="🧹",
            category="maintenance",
        ),
        TaskTemplate(
            id="memory_backup",
            name="记忆备份",
            description="将记忆数据库导出到备份文件",
            task_type="backup",
            default_cron="0 2 * * 0",
            default_payload={"target": "memory", "format": "json"},
            icon="💾",
            category="maintenance",
        ),
        # Memory & Learning
        TaskTemplate(
            id="dream_consolidation",
            name="记忆巩固（梦境）",
            description="触发 REM + Deep Sleep 记忆整合，将工作记忆提升到语义层",
            task_type="dream",
            default_cron="0 4 * * *",
            default_payload={"phases": ["light", "rem", "deep"]},
            icon="🌙",
            category="memory",
        ),
        TaskTemplate(
            id="skill_evolution",
            name="技能进化",
            description="基于使用频率和成功率，自动优化和淘汰技能",
            task_type="skill_evolve",
            default_cron="0 5 * * 1",
            default_payload={"auto_approve": False, "max_evolutions": 3},
            icon="🧬",
            category="memory",
        ),
        # Information
        TaskTemplate(
            id="daily_report",
            name="每日总结报告",
            description="生成前一天的对话摘要、工具使用统计和token消耗报告",
            task_type="report",
            default_cron="0 9 * * *",
            default_payload={"report_type": "daily", "format": "markdown"},
            icon="📊",
            category="information",
        ),
        TaskTemplate(
            id="weekly_digest",
            name="每周摘要",
            description="生成本周关键洞察、高频话题和技能使用趋势",
            task_type="report",
            default_cron="0 10 * * 1",
            default_payload={"report_type": "weekly", "format": "markdown"},
            icon="📰",
            category="information",
        ),
        TaskTemplate(
            id="news_briefing",
            name="早间新闻简报",
            description="搜索指定话题的最新信息并生成摘要",
            task_type="search",
            default_cron="0 8 * * *",
            default_payload={"queries": ["AI 最新进展", "科技新闻"], "max_results": 5},
            icon="📰",
            category="information",
        ),
        # Custom
        # NOTE: there is intentionally no public "custom_shell" template.
        # Arbitrary scheduled shell commands are an admin-only capability:
        # the daemon refuses to run task_type="shell" jobs that were not
        # created with system_scope=True (see JSDaemon._cb_shell).
        TaskTemplate(
            id="gateway_daily_brief",
            name="渠道每日简报",
            description="向已配对渠道发送白名单每日简报模板（外发走 lease）",
            task_type="gateway_push",
            default_cron="0 9 * * *",
            default_payload={
                "template": "daily_brief",
                "channel": "discord",
                "peer_id": "",
            },
            icon="📣",
            category="information",
        ),
        TaskTemplate(
            id="custom_chat",
            name="自定义对话任务",
            description="定时向 Agent 发送指定提示词并记录回复",
            task_type="chat",
            default_cron="0 9 * * *",
            default_payload={"prompt": "总结一下昨天的工作", "model": ""},
            icon="💬",
            category="custom",
        ),
    ]
}


def list_templates(category: str | None = None) -> list[TaskTemplate]:
    """List available templates, optionally filtered by category."""
    templates = list(TEMPLATE_REGISTRY.values())
    if category:
        templates = [t for t in templates if t.category == category]
    return templates


def get_template(template_id: str) -> TaskTemplate | None:
    return TEMPLATE_REGISTRY.get(template_id)
