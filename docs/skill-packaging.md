# Skill Packaging

AutoSecAudit keeps the existing declarative YAML skill manifest as the machine-readable contract for:

- trigger matching
- risk and retry posture
- runtime dependencies
- follow-up chaining
- default parameters and result interpretation

The loader now also supports an optional per-skill companion directory for human-readable guidance and reusable resources.

## Supported layouts

### Legacy flat manifest with optional sidecar directory

```text
autosecaudit/skills/
├── cve_verify.yaml
└── cve_verify/
    ├── SKILL.md
    ├── docs/
    ├── scripts/
    ├── references/
    └── assets/
```

### Directory-native skill package

```text
autosecaudit/skills/
└── cve_verify/
    ├── skill.yaml
    ├── SKILL.md
    ├── docs/
    ├── scripts/
    ├── references/
    └── assets/
```

Both layouts are valid. Directory-native manifests take the skill directory itself as the resource root. Flat manifests use a same-name sibling directory when present.

## Resource responsibilities

- `*.yaml`: structured planner contract; keep trigger, risk, dependencies, follow-up, and result wiring here
- `SKILL.md`: natural-language operating intent, scope boundaries, result semantics, and reviewer notes
- `docs/`: longer audit playbooks, analyst runbooks, examples, or investigation notes
- `scripts/`: reusable helper scripts that multiple tool flows can call
- `references/`: structured or prose reference material that should stay outside the compact YAML manifest
- `assets/`: optional future output assets or templates

## Loader behavior

- The loader scans top-level `*.yaml` manifests for backward compatibility.
- The loader also scans immediate child directories for `skill.yaml`, `<dir-name>.yaml`, or a single unambiguous YAML manifest.
- When a resource root is found, the loader attaches optional `documentation` and `resources` metadata to the in-memory `SkillDefinition`.
- Existing planning and execution behavior continues to use the YAML manifest as the source of truth.
