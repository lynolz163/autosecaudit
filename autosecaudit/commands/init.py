"""Interactive initialization wizard for AutoSecAudit."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence

from autosecaudit.integrations.auth_profiles import FileLock


DEFAULT_CONFIG_PATH = Path.home() / ".autosecaudit" / "llm_router.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m autosecaudit init",
        description="Interactive setup wizard for AutoSecAudit model routing defaults.",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_CONFIG_PATH),
        help="Config output path (default: ~/.autosecaudit/llm_router.json)",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing config without confirmation prompt.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    output_path = Path(args.output).expanduser().resolve()

    if output_path.exists() and output_path.is_file() and not args.overwrite:
        if not _prompt_yes_no(
            f"Config file already exists: {output_path}\nOverwrite it?",
            default=False,
        ):
            print("Cancelled. Existing config was not modified.")
            return 0

    provider_choice = _prompt_choice(
        "Select the default LLM provider",
        choices=[
            ("1", "OpenAI"),
            ("2", "Codex (OAuth)"),
            ("3", "Local (OpenAI-compatible)"),
        ],
        default="1",
    )
    provider_label = {"1": "openai", "2": "codex", "3": "local"}[provider_choice]

    enable_codex_browser_oauth = False
    if provider_label == "codex":
        enable_codex_browser_oauth = _prompt_yes_no(
            "Enable Codex browser OAuth login (PKCE)?",
            default=True,
        )

    default_budget = _prompt_int(
        "Default budget for one audit task",
        default=120,
        min_value=1,
        max_value=100_000,
    )

    config = _build_default_config(
        provider_label=provider_label,
        enable_codex_browser_oauth=enable_codex_browser_oauth,
        default_budget=default_budget,
    )
    _write_json_with_lock(output_path, config)

    print("")
    print("Initialization completed.")
    print(f"Config written to: {output_path}")
    print("Use it with `--llm-config <path>` in plan/agent mode.")
    return 0


def _prompt_choice(title: str, *, choices: list[tuple[str, str]], default: str) -> str:
    print("")
    print(title)
    for key, label in choices:
        suffix = " (default)" if key == default else ""
        print(f"  {key}) {label}{suffix}")

    valid = {key for key, _label in choices}
    while True:
        raw = input(f"Enter choice [{default}]: ").strip()
        selected = raw or default
        if selected in valid:
            return selected
        print("Invalid choice. Please try again.")


def _prompt_yes_no(question: str, *, default: bool) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        raw = input(f"{question} [{hint}]: ").strip().lower()
        if not raw:
            return default
        if raw in {"y", "yes"}:
            return True
        if raw in {"n", "no"}:
            return False
        print("Please enter y or n.")


def _prompt_int(question: str, *, default: int, min_value: int, max_value: int) -> int:
    while True:
        raw = input(f"{question} [{default}]: ").strip()
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            print("Please enter an integer.")
            continue
        if value < min_value or value > max_value:
            print(f"Please enter a value between {min_value} and {max_value}.")
            continue
        return value


def _build_default_config(
    *,
    provider_label: str,
    enable_codex_browser_oauth: bool,
    default_budget: int,
) -> dict[str, Any]:
    if provider_label == "openai":
        primary_model = "openai/gpt-4.1-mini"
        default_provider = "openai"
        providers: dict[str, Any] = {
            "openai": {
                "type": "openai_sdk",
                "api_key_env": "OPENAI_API_KEY",
                "timeout_seconds": 180,
            }
        }
    elif provider_label == "codex":
        primary_model = "codex/your-model-id"
        default_provider = "codex"
        providers = {
            "codex": {
                "type": "codex_oauth",
                "base_url": "https://api.openai.com/v1",
                "oauth_profile_id": "default",
                "oauth_profiles_file": str(Path.home() / ".autosecaudit" / "auth-profiles.json"),
                "oauth_auto_refresh": True,
                "oauth_browser_login": enable_codex_browser_oauth,
                "oauth_authorize_url": "https://<your-auth-server>/authorize",
                "oauth_token_url": "https://<your-auth-server>/token",
                "oauth_client_id": "<your_client_id>",
                "oauth_scopes": ["openid", "profile", "offline_access"],
                "oauth_redirect_host": "127.0.0.1",
                "oauth_redirect_port": 8765,
                "oauth_redirect_path": "/callback",
                "oauth_cache_file": str(Path.home() / ".autosecaudit" / "codex_oauth_token.json"),
                "oauth_login_timeout_seconds": 180,
            }
        }
    else:
        primary_model = "local/qwen2.5"
        default_provider = "local"
        providers = {
            "local": {
                "type": "openai_compatible",
                "base_url": "http://localhost:11434/v1",
                "api_key_env": "DUMMY_KEY",
                "timeout_seconds": 180,
            }
        }

    return {
        "primary_model": primary_model,
        "fallback_models": [],
        "default_provider": default_provider,
        "request": {
            "temperature": 0.0,
            "max_output_tokens": 1200,
        },
        "providers": providers,
        "autosecaudit": {
            "default_budget": int(default_budget),
            "strict_safe_mode": True,
            "agent_defaults": {
                "max_iterations": 6,
                "global_timeout": 900,
            },
        },
    }


def _write_json_with_lock(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with FileLock(lock_path):
        tmp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp_path.replace(path)
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
