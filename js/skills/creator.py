"""Interactive skill creation wizard with intelligent scaffolding.

Provides:
- Interactive Q&A flow for creating new skills
- Template-based generation for all skill types (prompt/code/workflow/meta)
- Automatic parameter inference from Python argparse
- Prerequisites detection
- One-shot install to the agent's skill directory
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from js.skills.spec import Prerequisites, SkillSpec, SkillType
from js.utils.log import get_logger

logger = get_logger("js.skills.creator")

DEFAULT_LICENSES = ["MIT", "Apache-2.0", "BSD-3-Clause", "GPL-3.0", "Proprietary"]
DEFAULT_CATEGORIES = [
    "general", "development", "devops", "data", "security",
    "communication", "research", "automation", "testing", "documentation",
]

# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

_PROMPT_TEMPLATE = """---
id: {id}
name: {name}
description: {description}
type: prompt
version: {version}
author: {author}
license: {license}
category: {category}
tags:
{tags_yaml}
trust_level: community
---

## Instructions

{instructions}

## Example Usage

When the user asks something like:
> {example_query}

Use the instructions above to help them.
"""

_CODE_TEMPLATE = """---
id: {id}
name: {name}
description: {description}
type: code
version: {version}
author: {author}
license: {license}
category: {category}
entry: {entry}
tags:
{tags_yaml}
trust_level: community
prerequisites:
  commands:
{prereq_commands_yaml}
  packages:
{prereq_packages_yaml}
execution:
  timeout_seconds: 30
  network_allowed: true
metadata:
  parameters:
{parameters_yaml}
---

## Overview

{name} is a code skill that executes `{entry}`.

## Parameters

{parameters_doc}

## Example

```bash
python main.py --help
```
"""

_CODE_MAIN_PY = '''"""{description}"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description={name!r})
{argparse_args}
    args = parser.parse_args()

    # Load skill arguments from environment (injected by JS Agent)
    skill_args = json.loads(os.environ.get("JS_SKILL_ARGS", "{{}}"))
    workspace = Path(os.environ.get("JS_SKILL_WORKSPACE", "."))

    # TODO: Implement your skill logic here
    print(f"Running {name} with args: {{args}}")
    print(f"Workspace: {{workspace}}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
'''

_WORKFLOW_TEMPLATE = """---
id: {id}
name: {name}
description: {description}
type: workflow
version: {version}
author: {author}
license: {license}
category: {category}
tags:
{tags_yaml}
trust_level: community
---

## Workflow Steps

```yaml
workflow:
  steps:
{steps_yaml}
```

## Parameters

{parameters_doc}
"""

_META_TEMPLATE = """---
id: {id}
name: {name}
description: {description}
type: meta
version: {version}
author: {author}
license: {license}
category: {category}
tags:
{tags_yaml}
trust_level: community
skill_dependencies:
{dependencies_yaml}
---

## Composition

This meta-skill orchestrates the following sub-skills:

{dependencies_doc}

## Workflow

```yaml
workflow:
  steps:
{steps_yaml}
```
"""


# ---------------------------------------------------------------------------
# Core creator API
# ---------------------------------------------------------------------------


def create_skill(
    skills_dir: Path,
    skill_id: str,
    name: str,
    description: str,
    skill_type: SkillType,
    *,
    category: str = "general",
    tags: list[str] | None = None,
    author: str = "unknown",
    license: str = "MIT",  # noqa: A002
    version: str = "0.1.0",
    instructions: str = "",
    example_query: str = "",
    entry: str = "main.py",
    parameters: list[dict[str, Any]] | None = None,
    prerequisites: Prerequisites | None = None,
    dependencies: list[str] | None = None,
    steps: list[dict[str, Any]] | None = None,
    _install: bool = True,
) -> Path:
    """Create a new skill from parameters.

    Args:
        skills_dir: Base directory for skills (e.g. ~/.js/skills/user/)
        skill_id: Unique identifier (kebab-case recommended)
        name: Human-readable name
        description: One-line description
        skill_type: CODE, PROMPT, WORKFLOW, or META
        category: Skill category
        tags: List of tags
        author: Author name
        license: License identifier
        version: Semantic version
        instructions: For PROMPT type: the instruction text
        example_query: For PROMPT type: example user query
        entry: For CODE type: entry file name
        parameters: For CODE/WORKFLOW: list of {{"name": "...", "type": "...", "description": "..."}}
        prerequisites: Runtime prerequisites
        dependencies: For META type: sub-skill IDs
        steps: For WORKFLOW/META type: workflow steps
        install: Whether to copy into the skill manager directory

    Returns:
        Path to the created skill directory.
    """
    if not skill_id:
        raise ValueError("skill_id is required")
    if not name:
        raise ValueError("name is required")

    target_dir = skills_dir / skill_id
    if target_dir.exists():
        raise FileExistsError(f"Skill directory already exists: {target_dir}")
    target_dir.mkdir(parents=True, exist_ok=False)

    tags = tags or []
    tags_yaml = _to_yaml_list(tags) if tags else "  []"
    prereqs = prerequisites or Prerequisites()
    prereq_commands_yaml = _to_yaml_list(prereqs.commands) if prereqs.commands else "    - python3"
    prereq_packages_yaml = _to_yaml_list(prereqs.packages) if prereqs.packages else "    # none"
    params = parameters or []
    params_doc = _build_parameters_doc(params)
    deps = dependencies or []
    deps_yaml = _to_yaml_list(deps) if deps else "  # none"
    deps_doc = _build_dependencies_doc(deps)
    wf_steps = steps or []
    steps_yaml = _build_steps_yaml(wf_steps) if wf_steps else "    - type: prompt\n      input: Hello world"

    # Generate SKILL.md
    if skill_type == SkillType.PROMPT:
        skill_md = _PROMPT_TEMPLATE.format(
            id=skill_id, name=name, description=description,
            version=version, author=author, license=license,
            category=category, tags_yaml=tags_yaml,
            instructions=instructions or "Add your instructions here.",
            example_query=example_query or "How do I...?",
        )
    elif skill_type == SkillType.CODE:
        params_yaml = _build_parameters_yaml(params)
        skill_md = _CODE_TEMPLATE.format(
            id=skill_id, name=name, description=description,
            version=version, author=author, license=license,
            category=category, entry=entry, tags_yaml=tags_yaml,
            prereq_commands_yaml=prereq_commands_yaml,
            prereq_packages_yaml=prereq_packages_yaml,
            parameters_doc=params_doc,
            parameters_yaml=params_yaml,
        )
        # Generate entry file
        entry_path = target_dir / entry
        argparse_args = _build_argparse_code(params)
        entry_content = _CODE_MAIN_PY.format(
            description=description, name=name, argparse_args=argparse_args,
        )
        entry_path.write_text(entry_content, encoding="utf-8")
    elif skill_type == SkillType.WORKFLOW:
        skill_md = _WORKFLOW_TEMPLATE.format(
            id=skill_id, name=name, description=description,
            version=version, author=author, license=license,
            category=category, tags_yaml=tags_yaml,
            parameters_doc=params_doc, steps_yaml=steps_yaml,
        )
    elif skill_type == SkillType.META:
        skill_md = _META_TEMPLATE.format(
            id=skill_id, name=name, description=description,
            version=version, author=author, license=license,
            category=category, tags_yaml=tags_yaml,
            dependencies_yaml=deps_yaml, dependencies_doc=deps_doc,
            steps_yaml=steps_yaml,
        )
    else:
        raise ValueError(f"Unsupported skill type: {skill_type}")

    (target_dir / "SKILL.md").write_text(skill_md, encoding="utf-8")

    # Create sub-directories (Hermes-compatible)
    for subdir in ("references", "templates", "assets"):
        (target_dir / subdir).mkdir(exist_ok=True)
        # Add a .gitkeep so they survive git
        (target_dir / subdir / ".gitkeep").write_text("", encoding="utf-8")

    logger.info(f"Created skill: {skill_id} at {target_dir}")
    return target_dir


# ---------------------------------------------------------------------------
# Interactive wizard
# ---------------------------------------------------------------------------


def run_interactive_wizard(skills_dir: Path) -> Path:
    """Run an interactive CLI wizard to create a new skill.

    Returns the path to the created skill directory.
    """
    print("\n🛠️  JS Agent Skill Creator\n")
    print("Answer a few questions to scaffold your new skill.\n")

    # Skill ID
    skill_id = _ask("Skill ID (kebab-case, e.g. 'docker-lint')", validate=_validate_id)
    name = _ask("Display name", default=skill_id.replace("-", " ").title())
    description = _ask("One-line description")

    # Type
    print("\nSkill types:")
    print("  1. prompt   — LLM instruction template (like a system prompt)")
    print("  2. code     — Executable Python/Shell script")
    print("  3. workflow — YAML-defined step chain")
    print("  4. meta     — Composed of other skills")
    type_choice = _ask_choice("Choose type", ["prompt", "code", "workflow", "meta"], default="prompt")
    skill_type = SkillType(type_choice)

    # Metadata
    print("\n--- Metadata ---")
    category = _ask_choice("Category", DEFAULT_CATEGORIES, default="general")
    tags_input = _ask("Tags (comma-separated)", default="")
    tags = [t.strip() for t in tags_input.split(",") if t.strip()]
    author = _ask("Author", default=_guess_author())
    license_choice = _ask_choice("License", DEFAULT_LICENSES, default="MIT")

    # Type-specific fields
    instructions = ""
    example_query = ""
    entry = "main.py"
    parameters: list[dict[str, Any]] = []
    prerequisites = Prerequisites()
    dependencies: list[str] = []
    steps: list[dict[str, Any]] = []

    if skill_type == SkillType.PROMPT:
        print("\n--- Prompt Skill ---")
        example_query = _ask("Example user query this skill handles", default="How do I...?")
        print("Enter the skill instructions (end with a blank line):")
        lines: list[str] = []
        while True:
            line = input("| ")
            if line == "":
                break
            lines.append(line)
        instructions = "\n".join(lines) if lines else "Add your instructions here."

    elif skill_type == SkillType.CODE:
        print("\n--- Code Skill ---")
        entry = _ask("Entry file", default="main.py")
        print("Add parameters for your script (leave name blank to finish):")
        while True:
            pname = _ask("  Parameter name", default="")
            if not pname:
                break
            ptype = _ask_choice("  Type", ["string", "integer", "number", "boolean"], default="string")
            pdesc = _ask("  Description", default=f"{pname} parameter")
            preq = _ask_yesno("  Required?", default=True)
            parameters.append({"name": pname, "type": ptype, "description": pdesc, "required": preq})

        print("Add prerequisites (leave blank to finish):")
        cmd = _ask("  Required command (e.g. 'docker')", default="")
        if cmd:
            prerequisites.commands = [cmd]

    elif skill_type == SkillType.WORKFLOW:
        print("\n--- Workflow Skill ---")
        print("Define workflow steps (leave type blank to finish):")
        while True:
            stype = _ask("  Step type (prompt/shell/skill)", default="")
            if not stype:
                break
            sinput = _ask("  Step input / command")
            steps.append({"type": stype, "input": sinput})

    elif skill_type == SkillType.META:
        print("\n--- Meta Skill ---")
        print("Add sub-skill dependencies (leave blank to finish):")
        while True:
            dep = _ask("  Skill ID", default="")
            if not dep:
                break
            dependencies.append(dep)
        print("Define orchestration steps:")
        while True:
            stype = _ask("  Step type (skill/prompt/shell)", default="")
            if not stype:
                break
            if stype == "skill":
                sid = _ask("    Sub-skill ID")
                steps.append({"type": "skill", "skill_id": sid})
            else:
                sinput = _ask("    Input")
                steps.append({"type": stype, "input": sinput})

    print("\n--- Creating skill... ---")
    path = create_skill(
        skills_dir=skills_dir,
        skill_id=skill_id,
        name=name,
        description=description,
        skill_type=skill_type,
        category=category,
        tags=tags,
        author=author,
        license=license_choice,
        instructions=instructions,
        example_query=example_query,
        entry=entry,
        parameters=parameters,
        prerequisites=prerequisites,
        dependencies=dependencies,
        steps=steps,
    )
    print(f"\n✅ Created skill at: {path}")
    print("\nNext steps:")
    print(f"  1. Edit {path / 'SKILL.md'}")
    if skill_type == SkillType.CODE:
        print(f"  2. Implement logic in {path / entry}")
        print(f"  3. Run: js skill validate {path}")
        print(f"  4. Run: js skill test {path}")
    else:
        print(f"  2. Run: js skill validate {path}")
    print(f"  5. Run: js skill package {path}")
    return path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ask(prompt: str, default: str = "", validate: Any | None = None) -> str:
    """Ask a question and return the answer."""
    suffix = f" [{default}]" if default else ""
    while True:
        try:
            answer = input(f"{prompt}{suffix}: ").strip()
        except EOFError:
            answer = ""
        value = answer if answer else default
        if validate:
            error = validate(value)
            if error:
                print(f"  [Error] {error}")
                continue
        return value


def _ask_choice(prompt: str, options: list[str], default: str = "") -> str:
    """Ask the user to choose from a list of options."""
    if default and default in options:
        default_idx = options.index(default)
        display = f"{prompt} (1-{len(options)}, default {default_idx + 1})"
    else:
        display = f"{prompt} (1-{len(options)})"

    for i, opt in enumerate(options, 1):
        marker = " *" if opt == default else ""
        print(f"  {i}. {opt}{marker}")

    answer = _ask(display, default="")
    if answer.isdigit():
        idx = int(answer) - 1
        if 0 <= idx < len(options):
            return options[idx]
    if answer in options:
        return answer
    return default


def _ask_yesno(prompt: str, default: bool = True) -> bool:
    """Ask a yes/no question."""
    suffix = " [Y/n]" if default else " [y/N]"
    answer = input(f"{prompt}{suffix}: ").strip().lower()
    if not answer:
        return default
    return answer.startswith("y")


def _validate_id(value: str) -> str | None:
    """Validate skill ID format. Returns error message or None."""
    if not value:
        return "Skill ID is required"
    if not re.match(r"^[a-z0-9]+(-[a-z0-9]+)*$", value):
        return "Skill ID must be kebab-case (lowercase letters, numbers, hyphens)"
    return None


def _guess_author() -> str:
    """Guess the author name from git config or environment."""
    try:
        import subprocess
        result = subprocess.run(
            ["git", "config", "user.name"],
            capture_output=True, text=True, timeout=2,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        logger.warning('Operation failed', exc_info=True)
    import getpass
    return getpass.getuser()


def _to_yaml_list(items: list[str]) -> str:
    """Convert a list of strings to YAML list format."""
    if not items:
        return ""
    return "\n".join(f"  - {item}" for item in items)


def _build_parameters_doc(params: list[dict[str, Any]]) -> str:
    """Build markdown documentation for parameters."""
    if not params:
        return "_No parameters defined._"
    lines: list[str] = []
    for p in params:
        req = " (required)" if p.get("required") else ""
        lines.append(f"- `{p['name']}` ({p.get('type', 'string')}){req}: {p.get('description', '')}")
    return "\n".join(lines)


def _build_parameters_yaml(params: list[dict[str, Any]]) -> str:
    """Build YAML for parameters metadata."""
    if not params:
        return "    # none"
    lines: list[str] = []
    for p in params:
        lines.append(f"    - name: {p['name']}")
        lines.append(f"      type: {p.get('type', 'string')}")
        lines.append(f"      description: {p.get('description', '')}")
        lines.append(f"      required: {p.get('required', False)}")
    return "\n".join(lines)


def _build_dependencies_doc(deps: list[str]) -> str:
    """Build markdown documentation for dependencies."""
    if not deps:
        return "_No dependencies._"
    return "\n".join(f"- `{dep}`" for dep in deps)


def _build_steps_yaml(steps: list[dict[str, Any]]) -> str:
    """Build YAML for workflow steps."""
    lines: list[str] = []
    for s in steps:
        lines.append(f"    - type: {s['type']}")
        if "input" in s:
            lines.append(f"      input: {s['input']}")
        if "skill_id" in s:
            lines.append(f"      skill_id: {s['skill_id']}")
        if "condition" in s:
            cond = s["condition"]
            lines.append("      condition:")
            lines.append(f"        if: {cond.get('if', '')}")
            lines.append(f"        eq: {cond.get('eq', '')}")
    return "\n".join(lines)


def _build_argparse_code(params: list[dict[str, Any]]) -> str:
    """Generate argparse.add_argument() calls from parameter specs."""
    if not params:
        return "    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')"
    lines: list[str] = []
    for p in params:
        name = p["name"]
        ptype = p.get("type", "string")
        desc = p.get("description", f"{name} parameter")
        required = p.get("required", False)

        if ptype == "boolean":
            lines.append(f"    parser.add_argument('--{name}', action='store_true', help={desc!r})")
        elif ptype == "integer":
            lines.append(
                f"    parser.add_argument('--{name}', type=int, required={required!r}, help={desc!r})"
            )
        elif ptype == "number":
            lines.append(
                f"    parser.add_argument('--{name}', type=float, required={required!r}, help={desc!r})"
            )
        else:
            lines.append(
                f"    parser.add_argument('--{name}', type=str, required={required!r}, help={desc!r})"
            )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Batch / non-interactive creation
# ---------------------------------------------------------------------------


def create_from_spec(skills_dir: Path, spec: SkillSpec, *, install: bool = True) -> Path:
    """Create a skill directory from an existing SkillSpec (useful for imports)."""
    params: list[dict[str, Any]] = []
    if spec.metadata and "parameters" in spec.metadata:
        params = spec.metadata["parameters"]

    steps: list[dict[str, Any]] = []
    if spec.metadata and "workflow" in spec.metadata:
        steps = spec.metadata["workflow"].get("steps", [])

    return create_skill(
        skills_dir=skills_dir,
        skill_id=spec.id,
        name=spec.name,
        description=spec.description,
        skill_type=spec.type,
        category=spec.category,
        tags=spec.tags,
        author=spec.author,
        license=spec.license,
        version=spec.version,
        entry=spec.entry,
        parameters=params,
        prerequisites=spec.prerequisites,
        dependencies=spec.dependencies,
        steps=steps,
        _install=install,
    )
