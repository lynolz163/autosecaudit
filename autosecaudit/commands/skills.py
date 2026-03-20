"""Inspect packaged AutoSecAudit skills from the CLI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from autosecaudit.agent_core.skill_loader import SkillDefinition, default_skill_directory, load_builtin_skill_registry


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m autosecaudit skills",
        description="List and inspect the built-in skill packs that ship with AutoSecAudit.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="List built-in skills.")
    list_parser.add_argument("--json", action="store_true", help="Print JSON instead of a table.")

    show_parser = subparsers.add_parser("show", help="Show one skill definition.")
    show_parser.add_argument("name", help="Skill name or bound tool name.")
    show_parser.add_argument("--json", action="store_true", help="Print JSON instead of a text summary.")
    return parser


def _serialize_skill(skill: SkillDefinition) -> dict[str, object]:
    return {
        "name": skill.name,
        "tool": skill.tool,
        "category": skill.category,
        "description": skill.description,
        "version": skill.version,
        "risk": {
            "level": skill.risk.level,
            "cost": skill.risk.cost,
            "priority": skill.risk.priority,
        },
        "triggers": {
            "phase": skill.triggers.phase,
            "target_source": skill.triggers.target_source,
            "target_type": skill.triggers.target_type,
            "when": [
                {"condition": item.condition, "config": item.config}
                for item in skill.triggers.when
            ],
        },
        "dependencies": {
            "runtime": skill.dependencies.runtime,
            "tools": skill.dependencies.tools,
        },
        "documentation": {
            "instruction_path": str(skill.documentation.instruction_path) if skill.documentation.instruction_path else None,
            "docs_dir": str(skill.documentation.docs_dir) if skill.documentation.docs_dir else None,
        },
        "source_path": str(skill.source_path) if skill.source_path else None,
    }


def _print_skill_table(skills: list[SkillDefinition]) -> None:
    if not skills:
        print("no skills")
        return
    print(f"skill_dir\t{default_skill_directory()}")
    for skill in skills:
        print(
            "{name}\t{tool}\t{category}\t{cost}\t{priority}\t{runtime}".format(
                name=skill.name,
                tool=skill.tool,
                category=skill.category,
                cost=skill.risk.cost,
                priority=skill.risk.priority,
                runtime=skill.dependencies.runtime or "-",
            )
        )


def _print_skill_summary(skill: SkillDefinition) -> None:
    print(f"name: {skill.name}")
    print(f"tool: {skill.tool}")
    print(f"category: {skill.category}")
    print(f"description: {skill.description}")
    print(f"version: {skill.version}")
    print(f"risk: level={skill.risk.level} cost={skill.risk.cost} priority={skill.risk.priority}")
    print(f"triggers.phase: {', '.join(skill.triggers.phase) or '-'}")
    print(f"triggers.target_source: {skill.triggers.target_source or '-'}")
    print(f"triggers.target_type: {skill.triggers.target_type or '-'}")
    if skill.triggers.when:
        print("triggers.when:")
        for item in skill.triggers.when:
            print(f"  - {item.condition}")
    print(f"runtime: {skill.dependencies.runtime or '-'}")
    print(f"related_tools: {', '.join(skill.dependencies.tools) or '-'}")
    if skill.documentation.instruction_path:
        print(f"instruction: {skill.documentation.instruction_path}")
    if skill.documentation.docs_dir:
        print(f"docs: {skill.documentation.docs_dir}")
    if skill.source_path:
        print(f"manifest: {skill.source_path}")


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    registry = load_builtin_skill_registry()

    if args.command == "list":
        skills = registry.list()
        if args.json:
            print(json.dumps([_serialize_skill(skill) for skill in skills], ensure_ascii=False, indent=2))
        else:
            _print_skill_table(skills)
        return 0

    skill = registry.get(str(args.name))
    if skill is None:
        print(f"skill_not_found: {args.name}")
        return 2
    if args.json:
        print(json.dumps(_serialize_skill(skill), ensure_ascii=False, indent=2))
    else:
        _print_skill_summary(skill)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
