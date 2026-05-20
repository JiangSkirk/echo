"""Unified skill executor for code, prompt, and workflow types."""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from js.security.sandbox import SandboxExecutor
from js.skills.security import runtime_security_check
from js.skills.spec import SkillSpec, SkillType
from js.utils.log import get_logger

logger = get_logger("js.skills.executor")

# Type alias for LLM call function
LLMCaller = Callable[[str, str | None], Awaitable[str]]


async def execute_skill(
    spec: SkillSpec,
    args: dict[str, Any],
    workspace: Path,
    llm_caller: LLMCaller | None = None,
    sandbox: SandboxExecutor | None = None,
) -> dict[str, Any]:
    """Execute a skill based on its type.

    Args:
        spec: The skill specification
        args: Arguments passed to the skill
        workspace: Agent workspace directory
        llm_caller: Optional async function(text, context) -> str for PROMPT skills
        sandbox: Optional sandbox executor for CODE skills
    """
    if spec.type == SkillType.CODE:
        return await _execute_code(spec, args, workspace, sandbox)
    elif spec.type == SkillType.PROMPT:
        return await _execute_prompt(spec, args, llm_caller)
    elif spec.type == SkillType.WORKFLOW:
        return await _execute_workflow(spec, args, workspace, llm_caller, sandbox)
    elif spec.type == SkillType.META:
        return await _execute_meta(spec, args, workspace, llm_caller, sandbox)
    else:
        return {"success": False, "error": f"Unknown skill type: {spec.type}"}


def _build_hermes_cli_args(args: dict[str, Any]) -> list[str]:
    """Convert JS_SKILL_ARGS dict to CLI args for Hermes scripts.

    Supports both argparse and manual sys.argv parsers.
    Named args become --key value (space-separated, works for both styles).
    Use __args__ for positional arguments.
    """
    cli_args: list[str] = []
    pos_args = args.get("__args__")
    if pos_args is not None:
        if isinstance(pos_args, list):
            cli_args.extend(str(a) for a in pos_args)
        else:
            cli_args.append(str(pos_args))
    for k, v in args.items():
        if k.startswith("_") or k == "__args__":
            continue
        flag = f"--{k.replace('_', '-')}"
        if isinstance(v, bool):
            if v:
                cli_args.append(flag)
        else:
            cli_args.append(flag)
            cli_args.append(str(v))
    return cli_args


async def _execute_code(
    spec: SkillSpec,
    args: dict[str, Any],
    workspace: Path,
    sandbox: SandboxExecutor | None = None,
) -> dict[str, Any]:
    """Execute a code skill (Python or Shell) with sandbox and timeout."""
    if not spec.path:
        return {"success": False, "error": "Skill path not set"}

    entry_path = spec.path / spec.entry
    if not entry_path.exists():
        return {"success": False, "error": f"Entry file not found: {spec.entry}"}

    # Runtime security check (lightweight, runs on every execution)
    ok, warnings = runtime_security_check(spec)
    if not ok:
        logger.warning(f"Runtime security check blocked {spec.id}: {warnings}")
        return {
            "success": False,
            "error": f"Security check failed: {'; '.join(warnings)}",
            "security_blocked": True,
        }
    if warnings:
        logger.info(f"Runtime security warnings for {spec.id}: {warnings}")

    env = os.environ.copy()
    env["JS_SKILL_ARGS"] = json.dumps(args)
    env["JS_SKILL_WORKSPACE"] = str(workspace)

    # Hermes bridge: inject HERMES_HOME and adapt CLI args
    is_hermes = spec.id.startswith("hermes:")
    if is_hermes:
        from js.skills.hermes_bridge import _get_hermes_home
        env["HERMES_HOME"] = str(_get_hermes_home())

    # Determine interpreter
    is_python = spec.entry.endswith(".py")
    is_shell = spec.entry.endswith(".sh") or spec.entry.endswith(".bash")

    if is_python:
        cmd = [sys.executable, str(entry_path)]
    elif is_shell:
        cmd = ["bash", str(entry_path)]
        for k, v in args.items():
            env[f"JS_ARG_{k.upper()}"] = str(v)
    else:
        return {"success": False, "error": f"Unsupported entry type: {spec.entry}"}

    # Append Hermes-style CLI args for CODE skills
    if is_hermes and (is_python or is_shell):
        cmd.extend(_build_hermes_cli_args(args))

    # Use sandbox if available and appropriate
    if sandbox and spec.trust_level.value in ("community", "quarantine"):
        try:
            result = await sandbox.execute(
                cmd,
                cwd=str(spec.path),
                env=env,
                timeout=spec.timeout_seconds,
            )
            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr,
                "duration_ms": result.duration_ms,
                "killed": result.killed,
                "oom_killed": result.oom_killed,
            }
        except asyncio.CancelledError:
            raise
        except Exception as e:
            return {"success": False, "error": f"Sandbox execution failed: {e}"}

    # Direct execution (for trusted/builtin skills or when no sandbox)
    proc: asyncio.subprocess.Process | None = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            cwd=str(spec.path),
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=spec.timeout_seconds,
            )
        except TimeoutError:
            if proc:
                try:
                    proc.kill()
                    await proc.wait()
                except ProcessLookupError:
                    pass
            return {
                "success": False,
                "error": f"Skill timed out after {spec.timeout_seconds}s",
                "output": "",
            }
        return {
            "success": proc.returncode == 0,
            "output": stdout.decode("utf-8", errors="replace"),
            "error": stderr.decode("utf-8", errors="replace"),
        }
    except asyncio.CancelledError:
        if proc:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
        raise
    except Exception as e:
        return {"success": False, "error": f"Execution failed: {e}"}


def _substitute_hermes_vars(content: str, spec: SkillSpec, args: dict[str, Any]) -> str:
    """Replace Hermes template variables with actual values.

    Supported variables:
      - ${HERMES_SKILL_DIR} → skill directory path
      - ${HERMES_SESSION_ID} → session_id from args or empty
    """
    if "${HERMES_SKILL_DIR}" in content:
        skill_dir = str(spec.path) if spec.path else "."
        content = content.replace("${HERMES_SKILL_DIR}", skill_dir)
    if "${HERMES_SESSION_ID}" in content:
        session_id = args.get("session_id", args.get("_session_id", ""))
        content = content.replace("${HERMES_SESSION_ID}", str(session_id))
    return content


# Mapping from Hermes tool names to JS Agent equivalents.
# Applied to PROMPT skill content before serving to LLM.
# Only simple 1:1 function-name replacements that preserve call structure.
HERMES_TOOL_MAP = {
    "web_extract(": "browser_fetch(",
    "write_file(": "file_write(",
    "read_file(": "file_read(",
    "terminal(": "shell(",
    "execute_code(": "python(",
}


def _remap_hermes_tools(content: str) -> str:
    """Replace Hermes-specific tool calls with JS Agent equivalents."""
    for hermes_tool, js_tool in HERMES_TOOL_MAP.items():
        content = content.replace(hermes_tool, js_tool)
    # Replace skill_view("name") and skills_list() with comments to avoid
    # leaving unmatched parentheses from simple string replacement.
    import re
    content = re.sub(r'skill_view\s*\(\s*["\'][^"\']+["\']\s*\)', '# Skill viewed', content)
    content = re.sub(r'skills_list\s*\(\s*\)', '# Skills listed', content)
    return content


async def _execute_prompt(
    spec: SkillSpec,
    args: dict[str, Any],
    llm_caller: LLMCaller | None,
) -> dict[str, Any]:
    """Execute a prompt skill by injecting it into LLM context.

    For prompt skills, "execution" means returning the skill's instructions
    so the agent can use them. If an llm_caller is provided, we can also
    ask the LLM to apply the skill to the given args.
    """
    if not spec.full_content:
        return {"success": False, "error": "Prompt skill has no content"}

    # Build context from args
    arg_context = "\n".join(f"{k}: {v}" for k, v in args.items())

    content = spec.full_content

    # Substitute Hermes template variables
    content = _substitute_hermes_vars(content, spec, args)

    # Remap Hermes-specific tool calls to JS Agent equivalents
    content = _remap_hermes_tools(content)

    # Load referenced files if available
    if spec.references_dir and spec.references_dir.exists():
        refs: list[str] = []
        for ref_file in sorted(spec.references_dir.iterdir()):
            if ref_file.is_file():
                try:
                    refs.append(f"\n## {ref_file.name}\n{ref_file.read_text()}")
                except Exception:
                    pass
        if refs:
            content += "\n\n" + "\n".join(refs)

    # If LLM caller available, ask it to apply the skill
    if llm_caller:
        prompt = (
            f"Apply the following skill instructions to the given task.\n\n"
            f"## Skill: {spec.name}\n{spec.description}\n\n"
            f"## Instructions\n{content}\n\n"
            f"## Task Context\n{arg_context}\n\n"
            f"Please execute this skill and return the result."
        )
        try:
            result = await llm_caller(prompt, spec.id)
            return {"success": True, "output": result, "skill_applied": spec.id}
        except asyncio.CancelledError:
            raise
        except Exception as e:
            return {"success": False, "error": f"LLM application failed: {e}"}

    # Without LLM caller, return the skill content for manual use
    return {
        "success": True,
        "output": content,
        "skill_id": spec.id,
        "note": "Prompt skill returned for manual application (no LLM caller provided)",
    }


async def _execute_workflow(
    spec: SkillSpec,
    args: dict[str, Any],
    workspace: Path,
    llm_caller: LLMCaller | None,
    sandbox: SandboxExecutor | None = None,
) -> dict[str, Any]:
    """Execute a workflow skill — a lightweight chain of steps.

    Workflow skills use YAML metadata to define a sequence of actions.
    Now with proper error handling and step-level reporting.
    """
    workflow_steps = spec.metadata.get("workflow", {}).get("steps", [])
    if not workflow_steps:
        return {"success": False, "error": "Workflow skill has no steps defined"}

    results: list[dict[str, Any]] = []
    any_failed = False

    for i, step in enumerate(workflow_steps, 1):
        step_type = step.get("type", "prompt")
        step_input = step.get("input", "")
        condition = step.get("condition")

        # Check condition before executing step
        if condition:
            cond_key = condition.get("if")
            cond_value = condition.get("eq")
            if cond_key and args.get(cond_key) != cond_value:
                results.append({
                    "step": i,
                    "type": step_type,
                    "status": "skipped",
                    "reason": f"condition not met: {cond_key}={args.get(cond_key)} != {cond_value}",
                })
                continue

        # Substitute args into step input
        for k, v in args.items():
            step_input = step_input.replace(f"{{{k}}}", str(v))

        step_result: dict[str, Any] = {"step": i, "type": step_type}

        if step_type == "prompt" and llm_caller:
            try:
                output = await llm_caller(step_input, f"{spec.id}:step{i}")
                step_result.update({"status": "success", "output": output})
            except asyncio.CancelledError:
                step_result.update({"status": "cancelled"})
                any_failed = True
                results.append(step_result)
                break
            except Exception as e:
                step_result.update({"status": "error", "error": str(e)})
                any_failed = True
        elif step_type == "shell":
            try:
                proc = await asyncio.create_subprocess_exec(
                    *shlex.split(step_input),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(workspace),
                )
                try:
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=spec.timeout_seconds,
                    )
                    step_result.update({
                        "status": "success" if proc.returncode == 0 else "error",
                        "output": stdout.decode("utf-8", errors="replace"),
                        "error": stderr.decode("utf-8", errors="replace") if stderr else None,
                        "returncode": proc.returncode,
                    })
                    if proc.returncode != 0:
                        any_failed = True
                except TimeoutError:
                    try:
                        proc.kill()
                        await proc.wait()
                    except ProcessLookupError:
                        pass
                    step_result.update({
                        "status": "error",
                        "error": f"Step timed out after {spec.timeout_seconds}s",
                    })
                    any_failed = True
            except asyncio.CancelledError:
                step_result.update({"status": "cancelled"})
                any_failed = True
                results.append(step_result)
                break
            except Exception as e:
                step_result.update({"status": "error", "error": str(e)})
                any_failed = True
        elif step_type == "skill":
            # Reference another skill by ID
            sub_skill_id = step.get("skill_id")
            if sub_skill_id:
                step_result.update({
                    "status": "pending",
                    "skill_id": sub_skill_id,
                    "note": "Meta skill resolution required",
                })
            else:
                step_result.update({"status": "error", "error": "skill step missing skill_id"})
                any_failed = True
        else:
            step_result.update({"status": "success", "output": step_input})

        results.append(step_result)

    return {
        "success": not any_failed,
        "output": json.dumps(results, indent=2),
        "steps_executed": len(results),
        "steps_failed": sum(1 for r in results if r.get("status") == "error"),
    }


async def _execute_meta(
    spec: SkillSpec,
    args: dict[str, Any],
    workspace: Path,
    llm_caller: LLMCaller | None,
    sandbox: SandboxExecutor | None = None,
) -> dict[str, Any]:
    """Execute a meta skill by delegating to its dependency DAG.

    Meta skills are composed of other skills executed in order.
    The workflow in metadata defines the execution plan.
    """
    workflow_steps = spec.metadata.get("workflow", {}).get("steps", [])
    if not workflow_steps:
        return {"success": False, "error": "Meta skill has no workflow steps defined"}

    results: list[dict[str, Any]] = []
    any_failed = False

    for i, step in enumerate(workflow_steps, 1):
        step_type = step.get("type", "skill")
        if step_type != "skill":
            # For non-skill steps, delegate to workflow executor logic
            # (simplified: just record the step)
            results.append({
                "step": i,
                "type": step_type,
                "status": "skipped",
                "reason": "Meta skill only supports 'skill' step types directly",
            })
            continue

        sub_skill_id = step.get("skill_id")
        if not sub_skill_id:
            results.append({
                "step": i,
                "type": "skill",
                "status": "error",
                "error": "Missing skill_id in meta step",
            })
            any_failed = True
            continue

        # Pass through args with optional mapping
        arg_mapping = step.get("arg_mapping", {})
        step_args = {k: args.get(v, v) for k, v in arg_mapping.items()} if arg_mapping else args

        results.append({
            "step": i,
            "type": "skill",
            "skill_id": sub_skill_id,
            "args": step_args,
            "status": "pending",
            "note": f"Delegate to skill '{sub_skill_id}'",
        })

    return {
        "success": not any_failed,
        "output": json.dumps(results, indent=2),
        "steps_executed": len(results),
        "steps_failed": sum(1 for r in results if r.get("status") == "error"),
        "note": "Meta skill delegation plan generated",
    }
