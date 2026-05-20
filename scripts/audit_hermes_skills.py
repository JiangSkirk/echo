#!/usr/bin/env python3
"""Audit all Hermes skills for JS Agent compatibility."""

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from js.skills.hermes_bridge import load_all_hermes_skills, is_hermes_skill
from js.skills.executor import execute_skill
from js.skills.spec import SkillType

WORKSPACE = Path.home() / ".js" / "workspace"


def check_prompt_skill(spec) -> dict:
    """Check if a prompt skill is usable in JS Agent."""
    issues = []
    score = 100

    # Must have content
    if not spec.full_content:
        issues.append("No markdown content (empty full_content)")
        score -= 40

    # Content should not have unsubstituted Hermes vars (these get substituted at runtime)
    # But warn if there are other Hermes-specific constructs
    if spec.full_content:
        if "!`" in spec.full_content:
            issues.append("Uses inline shell expansion (!`cmd`) — disabled by default in JS Agent")
            score -= 15
        if "${HERMES_" in spec.full_content:
            # These get substituted — not an issue
            pass
        if "skill_view(" in spec.full_content or "skills_list(" in spec.full_content:
            issues.append("References Hermes-specific tool calls (skill_view, skills_list)")
            score -= 20
        if "web_extract(" in spec.full_content:
            issues.append("References Hermes web_extract tool — may not be available")
            score -= 10
        if "write_file(" in spec.full_content:
            issues.append("References Hermes write_file tool — JS Agent uses different tools")
            score -= 10

    # References check
    if spec.references_dir and spec.references_dir.exists():
        refs = list(spec.references_dir.iterdir())
        if refs:
            issues.append(f"Has {len(refs)} reference files (supported)")
            score += 5  # Bonus

    # Templates check
    if spec.templates_dir and spec.templates_dir.exists():
        tmpls = list(spec.templates_dir.iterdir())
        if tmpls:
            issues.append(f"Has {len(tmpls)} template files (supported)")
            score += 5

    # Prerequisites
    ok, missing = spec.prerequisites.check()
    if not ok:
        issues.append(f"Missing prerequisites: {missing}")
        score -= len(missing) * 10

    # Platform compatibility
    if not spec.is_compatible():
        issues.append(f"Incompatible platform (requires: {spec.platforms})")
        score -= 30

    return {
        "score": max(0, score),
        "issues": issues,
        "usable": score >= 60 and spec.is_compatible(),
    }


def check_code_skill(spec) -> dict:
    """Check if a code skill is usable in JS Agent."""
    issues = []
    score = 100

    if not spec.path:
        issues.append("No path set")
        score -= 50
        return {"score": 0, "issues": issues, "usable": False}

    entry = spec.path / spec.entry
    if not entry.exists():
        issues.append(f"Entry file not found: {spec.entry}")
        score -= 50
    else:
        # Check if it's executable
        if entry.suffix == ".py":
            issues.append(f"Python script: {spec.entry} (supported)")
        elif entry.suffix in (".sh", ".bash"):
            issues.append(f"Shell script: {spec.entry} (supported)")
        else:
            issues.append(f"Unknown script type: {entry.suffix}")
            score -= 20

    # Hermes CODE skills: JS Agent now auto-maps JS_SKILL_ARGS to CLI args
    # and injects HERMES_HOME. So we only flag issues, not penalize heavily.
    if entry.exists():
        content = entry.read_text(errors="ignore")
        if "JS_SKILL_ARGS" not in content and "os.environ" not in content:
            # JS Agent now auto-converts JS_SKILL_ARGS to CLI args for Hermes skills
            pass  # No penalty — CLI adapter handles this
        if "HERMES_HOME" in content:
            issues.append("Script references HERMES_HOME (now auto-injected)")
            # Bonus: we now support this
            score += 5

    # Prerequisites
    ok, missing = spec.prerequisites.check()
    if not ok:
        issues.append(f"Missing prerequisites: {missing}")
        score -= len(missing) * 10

    if not spec.is_compatible():
        issues.append(f"Incompatible platform (requires: {spec.platforms})")
        score -= 30

    return {
        "score": max(0, min(100, score)),
        "issues": issues,
        "usable": score >= 60 and spec.is_compatible() and entry.exists(),
    }


async def test_execute_prompt(spec) -> dict:
    """Actually execute a prompt skill and see what happens."""
    try:
        result = await execute_skill(spec, {"task": "test", "session_id": "audit"}, WORKSPACE)
        return {
            "success": result.get("success", False),
            "has_output": bool(result.get("output", "")),
            "error": result.get("error", ""),
            "note": result.get("note", ""),
        }
    except Exception as e:
        return {"success": False, "error": str(e), "has_output": False}


def _build_test_args(spec) -> dict[str, Any]:
    """Build reasonable test args from inferred parameter schema."""
    params = spec.metadata.get("parameters", []) if spec.metadata else []
    test_args: dict[str, Any] = {}
    for p in params:
        name = p["name"]
        ptype = p.get("type", "string")
        default = p.get("default")
        enum = p.get("enum")
        if default is not None:
            test_args[name] = default
        elif ptype == "boolean":
            test_args[name] = False
        elif ptype == "integer":
            test_args[name] = 1
        elif ptype == "number":
            test_args[name] = 1.0
        elif enum:
            test_args[name] = enum[0]
        else:
            test_args[name] = f"test_{name}"
    return test_args


async def test_execute_code(spec) -> dict:
    """Actually execute a code skill and see what happens."""
    try:
        # For Hermes skills, build test args from inferred schema
        test_args = _build_test_args(spec) if spec.id.startswith("hermes:") else {"test": True}
        result = await execute_skill(spec, test_args, WORKSPACE)
        return {
            "success": result.get("success", False),
            "has_output": bool(result.get("output", "")),
            "error": result.get("error", ""),
        }
    except Exception as e:
        return {"success": False, "error": str(e), "has_output": False}


async def main():
    print("=" * 80)
    print("HERMES SKILL AUDIT FOR JS AGENT")
    print("=" * 80)

    skills = load_all_hermes_skills()
    print(f"\nTotal Hermes skills discovered: {len(skills)}\n")

    categories = {
        "fully_usable": [],
        "partially_usable": [],
        "unusable": [],
        "needs_optimization": [],
    }

    results = []

    for skill_id in sorted(skills.keys()):
        spec = skills[skill_id]

        if spec.type == SkillType.PROMPT:
            analysis = check_prompt_skill(spec)
            exec_result = await test_execute_prompt(spec)
        elif spec.type == SkillType.CODE:
            analysis = check_code_skill(spec)
            exec_result = await test_execute_code(spec)
        else:
            analysis = {"score": 0, "issues": [f"Unsupported type: {spec.type}"], "usable": False}
            exec_result = {"success": False, "error": "Unsupported type"}

        # Cross-check: static analysis says usable but execution failed?
        if analysis["usable"] and not exec_result["success"] and exec_result.get("error"):
            analysis["issues"].append(f"Execution failed: {exec_result['error'][:100]}")
            analysis["score"] -= 20

        # Cross-check: static says unusable but execution worked?
        if not analysis["usable"] and exec_result["success"]:
            analysis["issues"].append("Static analysis flagged issues but execution succeeded")
            analysis["score"] += 10

        final_usable = analysis["score"] >= 60

        record = {
            "id": skill_id,
            "name": spec.name,
            "type": spec.type.value,
            "category": spec.category,
            "score": analysis["score"],
            "usable": final_usable,
            "execution_success": exec_result["success"],
            "issues": analysis["issues"],
        }
        results.append(record)

        if final_usable and exec_result["success"]:
            categories["fully_usable"].append(record)
        elif final_usable:
            categories["partially_usable"].append(record)
        elif analysis["score"] >= 30:
            categories["needs_optimization"].append(record)
        else:
            categories["unusable"].append(record)

    # Print summary
    print(f"\n{'CATEGORY':<25} {'COUNT':>8}")
    print("-" * 35)
    for cat, items in categories.items():
        print(f"{cat:<25} {len(items):>8}")

    # Print fully usable
    print(f"\n{'='*80}")
    print(f"FULLY USABLE ({len(categories['fully_usable'])})")
    print(f"{'='*80}")
    for r in categories["fully_usable"]:
        print(f"  ✓ {r['id']:<50} score={r['score']}")

    # Print partially usable
    if categories["partially_usable"]:
        print(f"\n{'='*80}")
        print(f"PARTIALLY USABLE — execution issues ({len(categories['partially_usable'])})")
        print(f"{'='*80}")
        for r in categories["partially_usable"]:
            print(f"  ⚠ {r['id']:<50} score={r['score']}")
            for issue in r["issues"]:
                print(f"      • {issue}")

    # Print needs optimization
    if categories["needs_optimization"]:
        print(f"\n{'='*80}")
        print(f"NEEDS OPTIMIZATION ({len(categories['needs_optimization'])})")
        print(f"{'='*80}")
        for r in categories["needs_optimization"]:
            print(f"  🔧 {r['id']:<50} score={r['score']}")
            for issue in r["issues"]:
                print(f"      • {issue}")

    # Print unusable
    if categories["unusable"]:
        print(f"\n{'='*80}")
        print(f"UNUSABLE ({len(categories['unusable'])})")
        print(f"{'='*80}")
        for r in categories["unusable"]:
            print(f"  ✗ {r['id']:<50} score={r['score']}")
            for issue in r["issues"]:
                print(f"      • {issue}")

    # Print optimization recommendations
    print(f"\n{'='*80}")
    print("OPTIMIZATION RECOMMENDATIONS")
    print(f"{'='*80}")

    # Group issues
    issue_counts = {}
    for r in results:
        for issue in r["issues"]:
            if not issue.startswith("Has ") and not issue.endswith("(supported)"):
                issue_counts[issue] = issue_counts.get(issue, 0) + 1

    print("\nMost common issues across all skills:")
    for issue, count in sorted(issue_counts.items(), key=lambda x: -x[1])[:15]:
        print(f"  [{count:>2}x] {issue}")

    # Save detailed JSON
    output_path = Path("hermes_audit_results.json")
    with open(output_path, "w") as f:
        json.dump({
            "summary": {k: len(v) for k, v in categories.items()},
            "top_issues": [{"issue": k, "count": v} for k, v in sorted(issue_counts.items(), key=lambda x: -x[1])],
            "skills": results,
        }, f, indent=2)
    print(f"\nDetailed results saved to: {output_path}")


if __name__ == "__main__":
    asyncio.run(main())
