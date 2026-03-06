"""Lightweight nuclei template capability index for CVE-aware planning."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import subprocess
import time
from typing import Any


_CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,8})", flags=re.IGNORECASE)
_TAG_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{1,48}", flags=re.IGNORECASE)
_PROTOCOL_HINTS = {
    "apache",
    "grafana",
    "http",
    "https",
    "jenkins",
    "joomla",
    "memcached",
    "mysql",
    "nginx",
    "openssh",
    "postgres",
    "postgresql",
    "redis",
    "smtp",
    "spring",
    "ssh",
    "ssl",
    "tls",
    "wordpress",
}


@dataclass(frozen=True)
class TemplateCapability:
    """One normalized template capability summary."""

    cve_id: str
    has_template: bool
    template_count: int = 0
    template_paths: list[str] = field(default_factory=list)
    protocol_tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "has_template": self.has_template,
            "template_count": int(self.template_count),
            "template_paths": list(self.template_paths),
            "protocol_tags": list(self.protocol_tags),
        }


class TemplateCapabilityIndex:
    """Index CVE-related nuclei templates and infer coarse protocol tags."""

    _CAPABILITY_CACHE: dict[str, TemplateCapability] | None = None
    _CACHE_LOADED_AT: float = 0.0

    @classmethod
    def get_capability(cls, cve_id: str) -> dict[str, Any]:
        normalized = str(cve_id).strip().upper()
        if not _CVE_RE.fullmatch(normalized):
            return TemplateCapability(cve_id=normalized, has_template=False).to_dict()
        capability = cls._load_index().get(normalized)
        if capability is None:
            capability = TemplateCapability(cve_id=normalized, has_template=False)
        return capability.to_dict()

    @classmethod
    def load_ids(cls) -> set[str]:
        return set(cls._load_index().keys())

    @classmethod
    def _load_index(cls) -> dict[str, TemplateCapability]:
        ttl_seconds = max(
            1,
            int(os.getenv("AUTOSECAUDIT_NUCLEI_TEMPLATE_CACHE_TTL_SECONDS", "600") or 600),
        )
        now = time.time()
        if (
            cls._CAPABILITY_CACHE is not None
            and (now - cls._CACHE_LOADED_AT) <= ttl_seconds
        ):
            return dict(cls._CAPABILITY_CACHE)

        raw_index = cls._scan_template_dirs()
        if not raw_index:
            raw_index = cls._scan_template_list_command()

        cls._CAPABILITY_CACHE = {
            cve_id: TemplateCapability(
                cve_id=cve_id,
                has_template=True,
                template_count=len(values.get("template_paths", [])) or int(values.get("template_count", 1) or 1),
                template_paths=sorted({str(item) for item in values.get("template_paths", []) if str(item).strip()})[:20],
                protocol_tags=sorted({str(item).strip().lower() for item in values.get("protocol_tags", []) if str(item).strip()})[:20],
            )
            for cve_id, values in raw_index.items()
            if _CVE_RE.fullmatch(cve_id)
        }
        cls._CACHE_LOADED_AT = now
        return dict(cls._CAPABILITY_CACHE)

    @classmethod
    def _scan_template_dirs(cls) -> dict[str, dict[str, Any]]:
        index: dict[str, dict[str, Any]] = {}
        for root in cls._candidate_roots():
            if not root.exists() or not root.is_dir():
                continue
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                if path.suffix.lower() not in {".yaml", ".yml", ".json"}:
                    continue
                path_upper = str(path).upper()
                cve_ids = {match.group(1).upper() for match in _CVE_RE.finditer(path_upper)}
                if not cve_ids:
                    try:
                        text = path.read_text(encoding="utf-8", errors="ignore")
                    except OSError:
                        text = ""
                    cve_ids = {match.group(1).upper() for match in _CVE_RE.finditer(text.upper())}
                else:
                    text = ""
                if not cve_ids:
                    continue
                tags = cls._infer_protocol_tags(path=path, text=text)
                for cve_id in cve_ids:
                    entry = index.setdefault(
                        cve_id,
                        {
                            "template_paths": [],
                            "protocol_tags": set(),
                            "template_count": 0,
                        },
                    )
                    entry["template_paths"].append(str(path))
                    entry["template_count"] = int(entry.get("template_count", 0) or 0) + 1
                    entry["protocol_tags"].update(tags)
        return index

    @classmethod
    def _scan_template_list_command(cls) -> dict[str, dict[str, Any]]:
        try:
            completed = subprocess.run(
                ["nuclei", "-tl", "-silent"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return {}
        if completed.returncode != 0:
            return {}
        output = f"{completed.stdout}\n{completed.stderr}"
        index: dict[str, dict[str, Any]] = {}
        for cve_id in {match.group(1).upper() for match in _CVE_RE.finditer(output.upper())}:
            index[cve_id] = {
                "template_paths": [],
                "protocol_tags": [],
                "template_count": 1,
            }
        return index

    @classmethod
    def _candidate_roots(cls) -> list[Path]:
        roots: list[Path] = []
        env_roots = str(os.getenv("AUTOSECAUDIT_NUCLEI_TEMPLATES_DIRS", "")).strip()
        if env_roots:
            for item in env_roots.split(","):
                token = str(item).strip()
                if token:
                    roots.append(Path(token).expanduser())
        single_root = str(os.getenv("NUCLEI_TEMPLATES_DIR", "")).strip()
        if single_root:
            roots.append(Path(single_root).expanduser())

        home = Path.home()
        roots.extend(
            [
                home / "nuclei-templates",
                home / ".local" / "nuclei-templates",
                Path("/root/nuclei-templates"),
                Path.cwd() / "nuclei-templates",
            ]
        )

        deduped: list[Path] = []
        seen: set[str] = set()
        for root in roots:
            key = str(root).lower()
            if key in seen:
                continue
            seen.add(key)
            deduped.append(root)
        return deduped

    @classmethod
    def _infer_protocol_tags(cls, *, path: Path, text: str) -> set[str]:
        combined = "\n".join([str(path).lower(), text[:4000].lower()])
        tags = {token.lower() for token in _TAG_RE.findall(combined)}

        extracted: set[str] = set()
        for hint in _PROTOCOL_HINTS:
            if hint in tags or hint in combined:
                extracted.add(hint)

        for line in text.splitlines()[:80]:
            stripped = line.strip()
            if not stripped.lower().startswith("tags:"):
                continue
            _, _, raw_tags = stripped.partition(":")
            for token in _TAG_RE.findall(raw_tags.lower()):
                if token in _PROTOCOL_HINTS:
                    extracted.add(token)
            break

        if "postgres" in extracted:
            extracted.add("postgresql")
        if "ssl" in extracted:
            extracted.add("tls")
        if "https" in extracted:
            extracted.add("http")
        if "ssh" in extracted:
            extracted.add("openssh")
        return extracted
