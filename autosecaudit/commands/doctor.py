"""Runtime diagnostics and readiness checks for AutoSecAudit."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request

from autosecaudit.agent_core.builtin_tools import load_builtin_agent_tools
from autosecaudit.agent_core.tool_registry import get_tool, list_tools
from autosecaudit.integrations import LLMRouter, LLMRouterError


@dataclass(frozen=True)
class DoctorCheck:
    """One doctor check item."""

    check_id: str
    status: str  # pass | warn | fail
    message: str
    detail: str | None = None


def build_parser() -> argparse.ArgumentParser:
    """Build parser for `autosecaudit doctor`."""
    parser = argparse.ArgumentParser(
        prog="autosecaudit doctor",
        description="Run environment and configuration readiness checks.",
    )
    parser.add_argument(
        "--workspace",
        default=str(Path.cwd()),
        help="Workspace path used for write checks. Default: current directory.",
    )
    parser.add_argument(
        "--llm-config",
        default=None,
        help="Optional LLM router config path to validate.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print JSON report instead of human-readable text.",
    )
    parser.add_argument(
        "--strict-warnings",
        action="store_true",
        help="Exit non-zero when warnings are present.",
    )
    return parser


def _python_version_check() -> DoctorCheck:
    minimum = (3, 10)
    current = sys.version_info[:3]
    if current < minimum:
        return DoctorCheck(
            check_id="python_version",
            status="fail",
            message=f"Python {minimum[0]}.{minimum[1]}+ required",
            detail=f"current={current[0]}.{current[1]}.{current[2]}",
        )
    return DoctorCheck(
        check_id="python_version",
        status="pass",
        message="Python version is supported",
        detail=f"current={current[0]}.{current[1]}.{current[2]}",
    )


def _workspace_writable_check(workspace: Path) -> list[DoctorCheck]:
    checks: list[DoctorCheck] = []
    resolved = workspace.resolve()
    if not resolved.exists() or not resolved.is_dir():
        return [
            DoctorCheck(
                check_id="workspace_exists",
                status="fail",
                message="Workspace path is invalid",
                detail=str(resolved),
            )
        ]

    checks.append(
        DoctorCheck(
            check_id="workspace_exists",
            status="pass",
            message="Workspace path is valid",
            detail=str(resolved),
        )
    )

    for relative in ("output", "config"):
        target = (resolved / relative).resolve()
        try:
            target.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(target),
                prefix="doctor_",
                suffix=".tmp",
                delete=True,
            ) as handle:
                handle.write("ok")
                handle.flush()
            checks.append(
                DoctorCheck(
                    check_id=f"writable_{relative}",
                    status="pass",
                    message=f"Writable directory check passed: {relative}",
                    detail=str(target),
                )
            )
        except OSError as exc:
            checks.append(
                DoctorCheck(
                    check_id=f"writable_{relative}",
                    status="fail",
                    message=f"Directory is not writable: {relative}",
                    detail=str(exc),
                )
            )
    return checks


def _tool_availability_checks() -> list[DoctorCheck]:
    checks: list[DoctorCheck] = []
    load_builtin_agent_tools()
    tool_names = list_tools()
    if not tool_names:
        return [
            DoctorCheck(
                check_id="tool_registry",
                status="fail",
                message="No tools registered in ToolRegistry",
                detail=None,
            )
        ]

    checks.append(
        DoctorCheck(
            check_id="tool_registry",
            status="pass",
            message="Tool registry loaded",
            detail=f"count={len(tool_names)}",
        )
    )

    for tool_name in tool_names:
        try:
            tool = get_tool(tool_name)
            available, reason = tool.check_availability()
        except Exception as exc:  # noqa: BLE001
            checks.append(
                DoctorCheck(
                    check_id=f"tool_{tool_name}",
                    status="fail",
                    message=f"Tool initialization failed: {tool_name}",
                    detail=str(exc),
                )
            )
            continue
        if available:
            checks.append(
                DoctorCheck(
                    check_id=f"tool_{tool_name}",
                    status="pass",
                    message=f"Tool available: {tool_name}",
                    detail=None,
                )
            )
        else:
            checks.append(
                DoctorCheck(
                    check_id=f"tool_{tool_name}",
                    status="warn",
                    message=f"Tool unavailable: {tool_name}",
                    detail=reason or "availability check failed",
                )
            )
    return checks


def _tool_version_checks() -> list[DoctorCheck]:
    checks: list[DoctorCheck] = []
    for tool_name, candidates in _tool_version_candidates():
        version = _resolve_tool_version(candidates)
        if version:
            checks.append(
                DoctorCheck(
                    check_id=f"{tool_name}_version",
                    status="pass",
                    message=f"{tool_name} version detected",
                    detail=version,
                )
            )
        else:
            checks.append(
                DoctorCheck(
                    check_id=f"{tool_name}_version",
                    status="warn",
                    message=f"{tool_name} version could not be determined",
                    detail="binary not found or version probe failed",
                )
            )
    return checks


def _tool_version_candidates() -> list[tuple[str, list[list[str]]]]:
    dirsearch_candidates: list[list[str]] = []
    dirsearch_bin = shutil.which("dirsearch") or shutil.which("dirsearch.py")
    if dirsearch_bin:
        dirsearch_candidates.append([dirsearch_bin, "--version"])
    dirsearch_py = Path("/opt/dirsearch/dirsearch.py")
    if dirsearch_py.exists():
        dirsearch_candidates.append([sys.executable, str(dirsearch_py), "--version"])
    dirsearch_candidates.append([sys.executable, "-m", "dirsearch", "--version"])

    return [
        ("nmap", [["nmap", "--version"]]),
        ("nuclei", [["nuclei", "-version"]]),
        ("dirsearch", dirsearch_candidates),
    ]


def _resolve_tool_version(candidates: list[list[str]]) -> str | None:
    for command in candidates:
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
                shell=False,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue
        combined = "\n".join(
            part.strip() for part in ((completed.stdout or ""), (completed.stderr or "")) if part.strip()
        ).strip()
        first_line = combined.splitlines()[0].strip() if combined else ""
        lowered = first_line.lower()
        if any(token in lowered for token in ("no module named", "not found", "is not recognized", "traceback")):
            continue
        if first_line:
            return first_line[:300]
    return None


def _runtime_posture_checks() -> list[DoctorCheck]:
    checks: list[DoctorCheck] = []
    builtin_flag = os.getenv("AUTOSECAUDIT_CODEX_OAUTH_BUILTIN_PRESET", "1").strip().lower()
    if builtin_flag in {"1", "true", "yes", "on"}:
        checks.append(
            DoctorCheck(
                check_id="codex_builtin_preset",
                status="warn",
                message="Codex builtin OAuth preset is enabled",
                detail=(
                    "Builtin preset can break when upstream auth parameters change; "
                    "prefer explicit authorize/token/client_id for stable skill execution."
                ),
            )
        )
    else:
        checks.append(
            DoctorCheck(
                check_id="codex_builtin_preset",
                status="pass",
                message="Codex builtin OAuth preset is disabled",
                detail=None,
            )
        )

    return checks


def _llm_config_check(path_text: str | None) -> DoctorCheck:
    if not path_text:
        return DoctorCheck(
            check_id="llm_config",
            status="pass",
            message="LLM config check skipped",
            detail="No --llm-config provided.",
        )
    path = Path(path_text).expanduser().resolve()
    if not path.exists() or not path.is_file():
        return DoctorCheck(
            check_id="llm_config",
            status="fail",
            message="LLM config file does not exist",
            detail=str(path),
        )
    try:
        router = LLMRouter.from_json_file(path)
    except LLMRouterError as exc:
        return DoctorCheck(
            check_id="llm_config",
            status="fail",
            message="LLM config is invalid",
            detail=str(exc),
        )
    except Exception as exc:  # noqa: BLE001
        return DoctorCheck(
            check_id="llm_config",
            status="fail",
            message="Failed to load LLM config",
            detail=str(exc),
        )
    return DoctorCheck(
        check_id="llm_config",
        status="pass",
        message="LLM config loaded",
        detail=(
            f"primary={router.config.primary_model}, "
            f"fallbacks={len(router.config.fallback_models)}, "
            f"default_provider={router.config.default_provider}"
        ),
    )


def _llm_connectivity_checks(path_text: str | None) -> list[DoctorCheck]:
    if not path_text:
        return [
            DoctorCheck(
                check_id="llm_connectivity",
                status="pass",
                message="LLM connectivity check skipped",
                detail="No --llm-config provided.",
            )
        ]

    path = Path(path_text).expanduser().resolve()
    try:
        router = LLMRouter.from_json_file(path)
    except Exception:
        return []

    if not router.config.providers:
        return [
            DoctorCheck(
                check_id="llm_connectivity",
                status="warn",
                message="LLM config contains no providers",
                detail=str(path),
            )
        ]

    checks: list[DoctorCheck] = []
    for provider_name, provider in router.config.providers.items():
        base_url = (provider.base_url or "").strip()
        if not base_url and provider.provider_type in {"openai_sdk", "codex_oauth"}:
            base_url = "https://api.openai.com/v1"
        if not base_url:
            checks.append(
                DoctorCheck(
                    check_id=f"llm_connectivity_{provider_name}",
                    status="warn",
                    message=f"LLM connectivity not checked for provider: {provider_name}",
                    detail="provider base_url is empty",
                )
            )
            continue
        endpoint = f"{base_url.rstrip('/')}/models"
        checks.append(_probe_llm_endpoint(provider_name=provider_name, endpoint=endpoint))
    return checks


def _probe_llm_endpoint(*, provider_name: str, endpoint: str) -> DoctorCheck:
    request = urllib_request.Request(
        url=endpoint,
        method="GET",
        headers={"User-Agent": "AutoSecAudit-Doctor/0.1"},
    )
    try:
        with urllib_request.urlopen(request, timeout=8) as response:
            code = int(getattr(response, "status", 200) or 200)
        return DoctorCheck(
            check_id=f"llm_connectivity_{provider_name}",
            status="pass",
            message=f"LLM endpoint reachable: {provider_name}",
            detail=f"{endpoint} responded HTTP {code}",
        )
    except urllib_error.HTTPError as exc:
        status = "pass" if exc.code < 500 else "warn"
        return DoctorCheck(
            check_id=f"llm_connectivity_{provider_name}",
            status=status,
            message=f"LLM endpoint reachable: {provider_name}" if status == "pass" else f"LLM endpoint unhealthy: {provider_name}",
            detail=f"{endpoint} responded HTTP {exc.code}",
        )
    except urllib_error.URLError as exc:
        return DoctorCheck(
            check_id=f"llm_connectivity_{provider_name}",
            status="warn",
            message=f"LLM endpoint unreachable: {provider_name}",
            detail=f"{endpoint} -> {exc}",
        )
    except OSError as exc:
        return DoctorCheck(
            check_id=f"llm_connectivity_{provider_name}",
            status="warn",
            message=f"LLM endpoint request failed: {provider_name}",
            detail=f"{endpoint} -> {exc}",
        )


def run_doctor(*, workspace: Path, llm_config: str | None) -> dict[str, Any]:
    """Run all checks and return a structured report."""
    checks: list[DoctorCheck] = []
    checks.append(_python_version_check())
    checks.extend(_workspace_writable_check(workspace))
    checks.extend(_tool_availability_checks())
    checks.extend(_tool_version_checks())
    checks.extend(_runtime_posture_checks())
    checks.append(_llm_config_check(llm_config))
    checks.extend(_llm_connectivity_checks(llm_config))

    summary = {
        "pass": sum(1 for item in checks if item.status == "pass"),
        "warn": sum(1 for item in checks if item.status == "warn"),
        "fail": sum(1 for item in checks if item.status == "fail"),
        "total": len(checks),
    }
    return {
        "summary": summary,
        "checks": [asdict(item) for item in checks],
    }


def _print_human(report: dict[str, Any]) -> None:
    summary = report.get("summary", {})
    print(
        "[doctor] summary: "
        f"pass={summary.get('pass', 0)} "
        f"warn={summary.get('warn', 0)} "
        f"fail={summary.get('fail', 0)} "
        f"total={summary.get('total', 0)}"
    )
    for item in report.get("checks", []):
        status = str(item.get("status", "")).upper().ljust(4)
        check_id = str(item.get("check_id", "unknown"))
        message = str(item.get("message", ""))
        detail = item.get("detail")
        print(f"- [{status}] {check_id}: {message}")
        if detail:
            print(f"    detail: {detail}")


def main(argv: list[str] | None = None) -> int:
    """Entrypoint for `autosecaudit doctor`."""
    args = build_parser().parse_args(argv)
    report = run_doctor(
        workspace=Path(args.workspace),
        llm_config=args.llm_config,
    )

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        _print_human(report)

    fail_count = int(report.get("summary", {}).get("fail", 0))
    warn_count = int(report.get("summary", {}).get("warn", 0))
    if fail_count > 0:
        return 1
    if args.strict_warnings and warn_count > 0:
        return 2
    return 0
