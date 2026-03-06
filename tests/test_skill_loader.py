from __future__ import annotations

import json

from autosecaudit.agent_core.skill_loader import SkillLoader, load_builtin_skill_registry


def test_builtin_skill_registry_loads_all_bundled_skills() -> None:
    registry = load_builtin_skill_registry()

    assert len(registry.list()) >= 24
    nmap_skill = registry.for_tool("nmap_scan")
    assert nmap_skill is not None
    assert nmap_skill.triggers.target_type == "host_seed"
    assert nmap_skill.risk.cost == 15


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
