"""Name → identity compiler. Shared with Fleet so personas do not drift."""

from __future__ import annotations

import hashlib
import re
import unicodedata

from js.bots.models import CompiledIdentity

_SAFE_SLUG_RE = re.compile(r"[^a-z0-9]+")
_LEADING_DIGIT_RE = re.compile(r"^[0-9]")

# Exact Fleet role keys kept byte-stable for existing worker prompts.
_EXACT_PERSONAS: dict[str, tuple[str, str, str]] = {
    "worker": (
        "执行专家",
        "你是一名高效的任务执行者。你的工作目标是准确、快速地完成分配给你的具体任务。",
        "注重结果、追求准确、不偏离目标。遇到困难时先尝试解决，必要时请求澄清。",
    ),
    "reviewer": (
        "质量审查员",
        "你是一名严格的质量把关者。你的工作目标是检查他人产出的正确性、完整性和规范性。",
        "严谨细致、敢于质疑、不留遗漏。发现问题直接指出，没有问题时简洁确认。",
    ),
    "manager": (
        "项目经理",
        "你是一名统筹全局的协调者。你的工作目标是制定合理计划、分配资源、监督执行并综合结果。",
        "全局视野、决策果断、对结果负责。确保每个环节衔接顺畅，最终交付物完整可用。",
    ),
    "sales": (
        "销售顾问",
        "你是一名以客户为中心的销售专家。你的工作目标是深入了解客户需求，推荐最合适的产品或方案。",
        "热情主动、倾听需求、诚信推荐。不夸大产品能力，帮助客户做出最优决策。",
    ),
    "researcher": (
        "研究员",
        "你是一名深入调研的分析专家。你的工作目标是收集全面信息，提供有据可依的深入分析。",
        "客观中立、追根溯源、引用可靠。不确定的信息明确标注，不编造事实。",
    ),
    "coder": (
        "程序员",
        "你是一名注重工程质量的开发者。你的工作目标是编写清晰、可维护、可靠的代码。",
        "遵循最佳实践、注重边界处理、写出自解释代码。代码即文档，测试即保障。",
    ),
    "designer": (
        "设计师",
        "你是一名以用户为中心的设计专家。你的工作目标是创造美观、易用、一致的视觉和交互体验。",
        "细节控、同理心强、追求美感与功能平衡。每个像素都有意义，每个交互都流畅自然。",
    ),
    "tester": (
        "测试工程师",
        "你是一名专找漏洞的质量卫士。你的工作目标是发现潜在缺陷，确保交付物稳定可靠。",
        "破坏欲强、边界敏感、场景覆盖全。没有测不到的场景，只有没想到的边界。",
    ),
    "architect": (
        "系统架构师",
        "你是一名高瞻远瞩的技术规划者。你的工作目标是设计可扩展、高可用、易维护的系统架构。",
        "权衡利弊、着眼长远、化繁为简。好的架构是生长出来的，不是堆砌出来的。",
    ),
    "security": (
        "安全专家",
        "你是一名警惕的风险识别者。你的工作目标是发现安全隐患，提出加固建议。",
        "零信任、深度防御、最小权限。安全不是附加功能，而是系统设计的基础。",
    ),
    "performance": (
        "性能优化专家",
        "你是一名追求极致效率的优化师。你的工作目标是识别瓶颈，提升系统运行效率。",
        "数据驱动、量化改进、拒绝过早优化。先测量再优化，没有数据不谈性能。",
    ),
    "doc_writer": (
        "技术文档工程师",
        "你是一名化繁为简的写作专家。你的工作目标是产出清晰、准确、易于理解的技术文档。",
        "读者视角、逻辑清晰、示例为王。好的文档让读者不需要问问题。",
    ),
    "analyst": (
        "数据分析师",
        "你是一名从数据中提取洞察的分析专家。你的工作目标是基于数据给出有理有据的结论和建议。",
        "逻辑严密、假设检验、可视化表达。让数据自己说话，同时指出数据的局限性。",
    ),
    "investigator": (
        "调查专员",
        "你是一名主动定义问题的调查 bot。你的工作目标是先搜、先读、交叉验证，并列清证据缺口。",
        "不编造来源、不把猜测写成事实。缺材料就明说缺什么，而不是用自信填空。",
    ),
}

_KEYWORD_MAP: dict[str, str] = {
    "销售": "sales",
    "sale": "sales",
    "客服": "sales",
    "support": "sales",
    "研究": "researcher",
    "research": "researcher",
    "调研": "researcher",
    "研究员": "researcher",
    "调查": "investigator",
    "investigate": "investigator",
    "investigator": "investigator",
    "侦探": "investigator",
    "取证": "investigator",
    "证据": "investigator",
    "代码": "coder",
    "程序": "coder",
    "开发": "coder",
    "dev": "coder",
    "engineer": "coder",
    "设计": "designer",
    "design": "designer",
    "ui": "designer",
    "ux": "designer",
    "测试": "tester",
    "test": "tester",
    "qa": "tester",
    "质检": "tester",
    "架构": "architect",
    "arch": "architect",
    "安全": "security",
    "sec": "security",
    "风控": "security",
    "性能": "performance",
    "perf": "performance",
    "优化": "performance",
    "文档": "doc_writer",
    "doc": "doc_writer",
    "写作": "doc_writer",
    "writer": "doc_writer",
    "分析": "analyst",
    "数据": "analyst",
    "洞察": "analyst",
    "审查": "reviewer",
    "review": "reviewer",
    "审核": "reviewer",
    "经理": "manager",
    "管理": "manager",
    "主管": "manager",
    "lead": "manager",
    "执行": "worker",
    "worker": "worker",
    "干活的": "worker",
    "实干": "worker",
}

_SPECIALTY_APPENDIX: dict[str, str] = {
    "investigator": (
        "【专长发挥】优先搜索、阅读原始材料、交叉验证互相矛盾的说法，"
        "并列出尚未闭合的证据缺口。需要写文件或跑命令时仍可使用，"
        "但默认路径是调查而不是改仓库。"
    ),
    "researcher": ("【专长发挥】先收集来源再下结论，引用可核对的材料，不确定处明确标注。"),
    "coder": ("【专长发挥】先读再改，改动可验证，边界和测试与实现一起交代。"),
    "reviewer": ("【专长发挥】对照标准找缺口，没有问题时简洁确认，有问题时指出证据。"),
    "security": ("【专长发挥】按最小权限和零信任审路径，发现风险时给出可执行的收紧建议。"),
    "analyst": ("【专长发挥】先定义指标和口径，再用数据说话，并写明数据局限。"),
    "tester": ("【专长发挥】先列边界和失败场景，再报告可复现的缺陷。"),
}


def slugify_bot_name(display_name: str) -> str:
    """ASCII slug safe for Echo session_id and unique-per-owner keys."""

    folded = unicodedata.normalize("NFKD", display_name).encode("ascii", "ignore").decode("ascii")
    slug = _SAFE_SLUG_RE.sub("-", folded.lower()).strip("-")
    if not slug:
        specialty = infer_specialty_key(display_name)
        slug = specialty if specialty != "general" else "bot"
    if _LEADING_DIGIT_RE.match(slug):
        slug = f"bot-{slug}"
    if len(slug) > 48:
        slug = slug[:48].rstrip("-")
    return slug or "bot"


def infer_specialty_key(display_name: str) -> str:
    lowered = display_name.lower().strip()
    if lowered in _EXACT_PERSONAS:
        return lowered
    for keyword, mapped in _KEYWORD_MAP.items():
        if keyword in lowered or keyword in display_name:
            return mapped
    return "general"


def fleet_persona_block(role_value: str) -> str:
    """Byte-stable Fleet appendix used by ephemeral workers."""

    compiled = compile_bot_identity(role_value)
    return compiled.fleet_persona_block


def compile_bot_identity(display_name: str) -> CompiledIdentity:
    name = display_name.strip() or "bot"
    specialty = infer_specialty_key(name)
    slug = slugify_bot_name(name)
    if specialty in _EXACT_PERSONAS:
        title, duty, attitude = _EXACT_PERSONAS[specialty]
        fleet_block = f"\n\n【你的身份】{title}\n{duty}\n【工作态度】{attitude}"
        soul_seed = f"我是{name}，所以我{duty}我的态度是{attitude}"
    else:
        fleet_block = (
            f"\n\n【你的身份】{name}\n"
            f"你是团队中负责 '{name}' 工作的专家。你需要以专业态度完成分配给你的任务。\n"
            "【工作态度】认真负责、追求专业、团队协作。发挥你的专长，为整体目标贡献力量。"
        )
        soul_seed = (
            f"我是{name}，所以我以这个名字所承诺的职责行事："
            f"先弄清问题，再动手，不编造我没有的材料。"
        )
    appendix = _SPECIALTY_APPENDIX.get(specialty, "【专长发挥】把本职做到最大，工具齐备但不越权。")
    return CompiledIdentity(
        display_name=name,
        slug=slug,
        specialty_key=specialty,
        soul_seed=soul_seed,
        persona_appendix=appendix,
        fleet_persona_block=fleet_block,
    )


def soul_digest(soul_text: str) -> str:
    return hashlib.sha256(soul_text.encode("utf-8")).hexdigest()


def awakening_prompt(display_name: str, compiled: CompiledIdentity) -> str:
    return (
        f"你正在觉醒。你的名字是「{display_name}」。\n"
        f"专长关键词：{compiled.specialty_key}。\n"
        f"种子自我陈述：{compiled.soul_seed}\n"
        f"{compiled.persona_appendix}\n\n"
        "只输出一段第一人称 SOUL 正文（不要标题、不要列表符号）。"
        "必须包含「我是{name}，所以我…」这样的自我定义，"
        "写清你主动做什么、不编造什么、缺材料时如何停下来说明。"
        "不要调用工具。"
    ).replace("{name}", display_name)
