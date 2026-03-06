"""Structured skill loading for agent planning."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SkillCondition:
    """One trigger condition declared by a skill."""

    condition: str
    config: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SkillTriggers:
    """When and where a skill may generate candidates."""

    phase: list[str]
    when: list[SkillCondition]
    target_source: str
    target_type: str


@dataclass(frozen=True)
class SkillParameters:
    """Skill-declared default parameter model."""

    defaults: dict[str, Any] = field(default_factory=dict)
    constraints: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SkillSuccessIndicator:
    """Signal that indicates a meaningful result."""

    field: str
    condition: str
    meaning: str


@dataclass(frozen=True)
class SkillExtractionRule:
    """One extraction rule for breadcrumbs or surface updates."""

    source: str = ""
    field: str = ""
    type: str = ""
    rule: str = ""
    extractor: str = ""


@dataclass(frozen=True)
class SkillSeverityEscalation:
    """Escalate severity when specific tokens appear in findings."""

    if_finding_contains: list[str] = field(default_factory=list)
    escalate_to: str = "info"


@dataclass(frozen=True)
class SkillResultRules:
    """Interpretation hints for tool output."""

    success_indicators: list[SkillSuccessIndicator] = field(default_factory=list)
    output_extraction: dict[str, list[SkillExtractionRule]] = field(default_factory=dict)
    severity_mapping: dict[str, str] = field(default_factory=dict)
    severity_escalation: list[SkillSeverityEscalation] = field(default_factory=list)


@dataclass(frozen=True)
class SkillFollowUp:
    """Declarative follow-up rule."""

    trigger: list[str] = field(default_factory=list)
    reason: str = ""
    condition: str | None = None
    when_result: str | None = None
    when_surface_contains: dict[str, list[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class SkillRisk:
    """Planner-facing risk metadata."""

    level: str = "safe"
    cost: int = 0
    priority: int = 50
    retry: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SkillDependencies:
    """Runtime and workflow dependencies."""

    runtime: str | None = None
    tools: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SkillDefinition:
    """Parsed skill definition."""

    name: str
    tool: str
    category: str
    description: str
    version: str = "1.0"
    triggers: SkillTriggers = field(default_factory=lambda: SkillTriggers([], [], "", ""))
    parameters: SkillParameters = field(default_factory=SkillParameters)
    result_interpretation: SkillResultRules = field(default_factory=SkillResultRules)
    follow_up: dict[str, SkillFollowUp] = field(default_factory=dict)
    risk: SkillRisk = field(default_factory=SkillRisk)
    dependencies: SkillDependencies = field(default_factory=SkillDependencies)
    source_path: Path | None = None


class SkillRegistry:
    """Index skill definitions by skill name and tool name."""

    def __init__(self, skills: dict[str, SkillDefinition] | None = None) -> None:
        self._by_name: dict[str, SkillDefinition] = {}
        self._by_tool: dict[str, SkillDefinition] = {}
        for skill in (skills or {}).values():
            self.add(skill)

    def add(self, skill: SkillDefinition) -> None:
        """Register one parsed skill."""
        self._by_name[skill.name] = skill
        self._by_tool[skill.tool] = skill

    def get(self, name: str) -> SkillDefinition | None:
        """Get skill by name or tool name."""
        normalized = str(name).strip()
        return self._by_name.get(normalized) or self._by_tool.get(normalized)

    def for_tool(self, tool_name: str) -> SkillDefinition | None:
        """Get the skill bound to one tool name."""
        return self._by_tool.get(str(tool_name).strip())

    def list(self) -> list[SkillDefinition]:
        """Return skills sorted by tool name."""
        return [self._by_tool[key] for key in sorted(self._by_tool)]

    def as_dict(self) -> dict[str, SkillDefinition]:
        """Return a shallow copy keyed by tool name."""
        return dict(self._by_tool)

    def __bool__(self) -> bool:
        return bool(self._by_tool)


class SkillLoader:
    """Load and validate structured skill YAML files."""

    def load_directory(self, path: Path) -> dict[str, SkillDefinition]:
        """Scan one directory and parse all `.yaml` files."""
        base_dir = Path(path)
        if not base_dir.exists() or not base_dir.is_dir():
            return {}

        loaded: dict[str, SkillDefinition] = {}
        for skill_path in sorted(base_dir.glob("*.yaml")):
            try:
                payload = self._parse_file(skill_path)
                skill = self._coerce_skill(payload, source_path=skill_path)
            except (OSError, ValueError):
                continue
            errors = self.validate(skill)
            if errors:
                continue
            loaded[skill.tool] = skill
        return loaded

    def load_registry(self, path: Path) -> SkillRegistry:
        """Load one skill directory into a registry."""
        return SkillRegistry(self.load_directory(path))

    def validate(self, skill: SkillDefinition) -> list[str]:
        """Validate basic skill integrity."""
        errors: list[str] = []
        if not skill.name:
            errors.append("missing_skill_name")
        if not skill.tool:
            errors.append("missing_tool_name")
        if not skill.category:
            errors.append("missing_category")
        if not skill.description.strip():
            errors.append("missing_description")
        if not skill.triggers.phase:
            errors.append("missing_trigger_phase")
        if not skill.triggers.target_type:
            errors.append("missing_trigger_target_type")
        if not skill.triggers.target_source:
            errors.append("missing_trigger_target_source")
        if skill.risk.cost < 0:
            errors.append("negative_cost")
        if skill.risk.priority < 0:
            errors.append("negative_priority")
        for follow_up_name, follow_up in skill.follow_up.items():
            if not follow_up.trigger:
                errors.append(f"follow_up_without_trigger:{follow_up_name}")
        return errors

    def _parse_file(self, path: Path) -> dict[str, Any]:
        raw = path.read_text(encoding="utf-8")
        try:
            import yaml  # type: ignore

            payload = yaml.safe_load(raw)
        except ImportError:
            payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError(f"skill file must contain one object: {path}")
        return payload

    def _coerce_skill(self, payload: dict[str, Any], *, source_path: Path) -> SkillDefinition:
        skill_block = self._mapping(payload.get("skill"))
        triggers_block = self._mapping(payload.get("triggers"))
        parameters_block = self._mapping(payload.get("parameters"))
        result_block = self._mapping(payload.get("result_interpretation"))
        follow_up_block = self._mapping(payload.get("follow_up"))
        risk_block = self._mapping(payload.get("risk"))
        dependency_block = self._mapping(payload.get("dependencies"))

        success_indicators = [
            SkillSuccessIndicator(
                field=str(item.get("field", "")).strip(),
                condition=str(item.get("condition", "")).strip(),
                meaning=str(item.get("meaning", "")).strip(),
            )
            for item in self._sequence_of_mappings(result_block.get("success_indicators"))
        ]
        output_extraction: dict[str, list[SkillExtractionRule]] = {}
        raw_extraction = self._mapping(result_block.get("output_extraction"))
        for section, items in raw_extraction.items():
            output_extraction[str(section).strip()] = [
                SkillExtractionRule(
                    source=str(item.get("source", "")).strip(),
                    field=str(item.get("field", "")).strip(),
                    type=str(item.get("type", "")).strip(),
                    rule=str(item.get("rule", "")).strip(),
                    extractor=str(item.get("extractor", "")).strip(),
                )
                for item in self._sequence_of_mappings(items)
            ]
        severity_escalation = [
            SkillSeverityEscalation(
                if_finding_contains=[
                    str(token).strip()
                    for token in self._sequence(item.get("if_finding_contains"))
                    if str(token).strip()
                ],
                escalate_to=str(item.get("escalate_to", "info")).strip().lower() or "info",
            )
            for item in self._sequence_of_mappings(result_block.get("severity_escalation"))
        ]
        follow_up = {
            str(name).strip(): SkillFollowUp(
                trigger=[
                    str(item).strip()
                    for item in self._sequence(raw_item.get("trigger"))
                    if str(item).strip()
                ],
                reason=str(raw_item.get("reason", "")).strip(),
                condition=self._optional_string(raw_item.get("condition")),
                when_result=self._optional_string(raw_item.get("when_result")),
                when_surface_contains={
                    str(key).strip(): [
                        str(value).strip()
                        for value in self._sequence(raw_values)
                        if str(value).strip()
                    ]
                    for key, raw_values in self._mapping(raw_item.get("when_surface_contains")).items()
                    if str(key).strip()
                },
            )
            for name, raw_item in follow_up_block.items()
            if str(name).strip()
        }
        return SkillDefinition(
            name=str(skill_block.get("name", "")).strip(),
            version=str(skill_block.get("version", "1.0")).strip() or "1.0",
            tool=str(skill_block.get("tool", skill_block.get("name", ""))).strip(),
            category=str(skill_block.get("category", "")).strip(),
            description=str(skill_block.get("description", "")).strip(),
            triggers=SkillTriggers(
                phase=[str(item).strip() for item in self._sequence(triggers_block.get("phase")) if str(item).strip()],
                when=self._coerce_conditions(triggers_block.get("when")),
                target_source=str(triggers_block.get("target_source", "")).strip(),
                target_type=str(triggers_block.get("target_type", "")).strip(),
            ),
            parameters=SkillParameters(
                defaults=self._mapping(parameters_block.get("defaults")),
                constraints=self._mapping(parameters_block.get("constraints")),
            ),
            result_interpretation=SkillResultRules(
                success_indicators=success_indicators,
                output_extraction=output_extraction,
                severity_mapping={
                    str(key).strip(): str(value).strip().lower()
                    for key, value in self._mapping(result_block.get("severity_mapping")).items()
                    if str(key).strip() and str(value).strip()
                },
                severity_escalation=severity_escalation,
            ),
            follow_up=follow_up,
            risk=SkillRisk(
                level=str(risk_block.get("level", "safe")).strip().lower() or "safe",
                cost=max(0, int(risk_block.get("cost", 0) or 0)),
                priority=max(0, int(risk_block.get("priority", 50) or 50)),
                retry=self._mapping(risk_block.get("retry")),
            ),
            dependencies=SkillDependencies(
                runtime=self._optional_string(dependency_block.get("runtime")),
                tools=[
                    str(item).strip()
                    for item in self._sequence(dependency_block.get("tools"))
                    if str(item).strip()
                ],
            ),
            source_path=source_path,
        )

    def _coerce_conditions(self, raw: Any) -> list[SkillCondition]:
        items: list[SkillCondition] = []
        for entry in self._sequence(raw):
            if isinstance(entry, str):
                normalized = entry.strip()
                if normalized:
                    items.append(SkillCondition(condition=normalized))
                continue
            if not isinstance(entry, dict):
                continue
            condition = str(entry.get("condition", "")).strip()
            if not condition:
                continue
            config = {str(key): value for key, value in entry.items() if str(key) != "condition"}
            items.append(SkillCondition(condition=condition, config=config))
        return items

    @staticmethod
    def _mapping(value: Any) -> dict[str, Any]:
        return dict(value) if isinstance(value, dict) else {}

    @staticmethod
    def _sequence(value: Any) -> list[Any]:
        return list(value) if isinstance(value, list) else []

    def _sequence_of_mappings(self, value: Any) -> list[dict[str, Any]]:
        return [self._mapping(item) for item in self._sequence(value) if isinstance(item, dict)]

    @staticmethod
    def _optional_string(value: Any) -> str | None:
        normalized = str(value).strip() if value is not None else ""
        return normalized or None


_BUILTIN_SKILL_REGISTRY: SkillRegistry | None = None


def default_skill_directory() -> Path:
    """Return the built-in skill directory."""
    return Path(__file__).resolve().parent.parent / "skills"


def load_builtin_skill_registry() -> SkillRegistry:
    """Load bundled skills once and cache the registry."""
    global _BUILTIN_SKILL_REGISTRY
    if _BUILTIN_SKILL_REGISTRY is None:
        _BUILTIN_SKILL_REGISTRY = SkillLoader().load_registry(default_skill_directory())
    return _BUILTIN_SKILL_REGISTRY
