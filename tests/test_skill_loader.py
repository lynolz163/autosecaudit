from __future__ import annotations

import json

from autosecaudit.agent_core.skill_loader import SkillLoader, load_builtin_skill_registry


def test_builtin_skill_registry_loads_all_bundled_skills() -> None:
    registry = load_builtin_skill_registry()
    skills = registry.list()

    assert len(skills) >= 24
    nmap_skill = registry.for_tool("nmap_scan")
    assert nmap_skill is not None
    assert nmap_skill.triggers.target_type == "host_seed"
    assert nmap_skill.risk.cost == 15
    for skill in skills:
        assert skill.documentation.instruction_path is not None, skill.name
        assert skill.documentation.docs_dir is not None, skill.name
        assert skill.resources.root_dir is not None, skill.name
        assert skill.resources.references_dir is not None, skill.name


def test_skill_loader_supports_json_encoded_yaml_files(tmp_path) -> None:
    payload = {
        "skill": {
            "name": "example_tool",
            "tool": "example_tool",
            "category": "recon",
            "description": "Example skill.",
        },
        "triggers": {
            "phase": ["passive_recon"],
            "when": [{"condition": "has_scope_target"}],
            "target_source": "scope",
            "target_type": "domain",
        },
        "parameters": {"defaults": {}, "constraints": {}},
        "result_interpretation": {},
        "follow_up": {},
        "risk": {"level": "safe", "cost": 1, "priority": 1},
        "dependencies": {"runtime": None, "tools": []},
    }
    (tmp_path / "example_tool.yaml").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    loaded = SkillLoader().load_directory(tmp_path)

    assert "example_tool" in loaded
    assert loaded["example_tool"].triggers.target_source == "scope"


def test_skill_loader_discovers_optional_sidecar_docs_and_resources(tmp_path) -> None:
    payload = {
        "skill": {
            "name": "example_tool",
            "tool": "example_tool",
            "category": "recon",
            "description": "Example skill.",
        },
        "triggers": {
            "phase": ["passive_recon"],
            "when": [{"condition": "has_scope_target"}],
            "target_source": "scope",
            "target_type": "domain",
        },
        "parameters": {"defaults": {}, "constraints": {}},
        "result_interpretation": {},
        "follow_up": {},
        "risk": {"level": "safe", "cost": 1, "priority": 1},
        "dependencies": {"runtime": None, "tools": []},
    }
    (tmp_path / "example_tool.yaml").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    sidecar_dir = tmp_path / "example_tool"
    (sidecar_dir / "docs").mkdir(parents=True)
    (sidecar_dir / "scripts").mkdir()
    (sidecar_dir / "references").mkdir()
    (sidecar_dir / "SKILL.md").write_text("# Example Tool\n", encoding="utf-8")
    (sidecar_dir / "docs" / "manual-audit.md").write_text("Check exposed endpoints.\n", encoding="utf-8")
    (sidecar_dir / "scripts" / "normalize.py").write_text("print('ok')\n", encoding="utf-8")
    (sidecar_dir / "references" / "semantics.md").write_text("Result semantics.\n", encoding="utf-8")

    loaded = SkillLoader().load_directory(tmp_path)
    skill = loaded["example_tool"]

    assert skill.documentation.instruction_path == sidecar_dir / "SKILL.md"
    assert skill.documentation.docs_dir == sidecar_dir / "docs"
    assert skill.resources.root_dir == sidecar_dir
    assert skill.resources.scripts_dir == sidecar_dir / "scripts"
    assert skill.resources.references_dir == sidecar_dir / "references"


def test_skill_loader_supports_directory_native_skill_packages(tmp_path) -> None:
    payload = {
        "skill": {
            "name": "directory_tool",
            "tool": "directory_tool",
            "category": "recon",
            "description": "Directory packaged skill.",
        },
        "triggers": {
            "phase": ["passive_recon"],
            "when": [{"condition": "has_scope_target"}],
            "target_source": "scope",
            "target_type": "domain",
        },
        "parameters": {"defaults": {}, "constraints": {}},
        "result_interpretation": {},
        "follow_up": {},
        "risk": {"level": "safe", "cost": 1, "priority": 1},
        "dependencies": {"runtime": None, "tools": []},
    }
    skill_dir = tmp_path / "directory_tool"
    (skill_dir / "docs").mkdir(parents=True)
    (skill_dir / "references").mkdir()
    (skill_dir / "skill.yaml").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (skill_dir / "SKILL.md").write_text("# Directory Tool\n", encoding="utf-8")

    loaded = SkillLoader().load_directory(tmp_path)
    skill = loaded["directory_tool"]

    assert skill.source_path == skill_dir / "skill.yaml"
    assert skill.documentation.instruction_path == skill_dir / "SKILL.md"
    assert skill.documentation.docs_dir == skill_dir / "docs"
    assert skill.resources.root_dir == skill_dir
    assert skill.resources.references_dir == skill_dir / "references"
