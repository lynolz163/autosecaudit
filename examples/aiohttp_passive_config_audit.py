"""Passive configuration exposure auditor based on aiohttp.

This script performs *read-only* HTTP GET checks against a target website to
identify common sensitive file exposures such as:
  - .git/config
  - .env
  - backup configuration files

Safety constraints implemented by design:
  1) Only GET requests are sent.
  2) No login attempt, no form submission, no POST/PUT/DELETE.
  3) Result is heuristic (status=200 + sensitive keyword match).
"""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urljoin

import aiohttp


# Default target and paths requested by the user.
DEFAULT_TARGET_URL = "http://target/"
DEFAULT_CHECK_PATHS = [".git/config", ".env", "config.php.bak"]


# Keywords used to confirm likely sensitive content leakage.
# Matching is case-insensitive.
PATH_KEYWORDS: dict[str, list[str]] = {
    ".git/config": [
        "[core]",
        "repositoryformatversion",
        "bare =",
        "remote \"origin\"",
    ],
    ".env": [
        "db_password",
        "secret_key",
        "api_key",
        "app_key",
        "database_url",
    ],
    "config.php.bak": [
        "<?php",
        "define(",
        "$db",
        "password",
    ],
}


@dataclass(frozen=True)
class AuditFinding:
    """One positive exposure finding."""

    path: str
    url: str
    status: int
    matched_keywords: list[str]
    snippet: str


def build_absolute_url(base_url: str, path: str) -> str:
    """Create an absolute URL for a candidate path."""
    normalized_base = base_url if base_url.endswith("/") else f"{base_url}/"
    # lstrip avoids accidental absolute-path override issues.
    return urljoin(normalized_base, path.lstrip("/"))


def choose_keywords(path: str) -> list[str]:
    """Return keyword list for the path; fallback to generic sensitive markers."""
    if path in PATH_KEYWORDS:
        return PATH_KEYWORDS[path]
    return ["password", "secret", "token", "api_key", "database"]


def extract_snippet(text: str, keyword: str, radius: int = 80) -> str:
    """Extract a short text snippet around the first matched keyword."""
    lower_text = text.lower()
    lower_kw = keyword.lower()
    pos = lower_text.find(lower_kw)
    if pos < 0:
        snippet = text[: radius * 2]
    else:
        start = max(0, pos - radius)
        end = min(len(text), pos + len(keyword) + radius)
        snippet = text[start:end]
    return " ".join(snippet.replace("\r", " ").replace("\n", " ").split())


async def fetch_and_check(
    session: aiohttp.ClientSession,
    base_url: str,
    path: str,
    timeout: aiohttp.ClientTimeout,
) -> AuditFinding | None:
    """Check a single path with GET and return finding when leakage is detected."""
    target_url = build_absolute_url(base_url, path)
    keywords = choose_keywords(path)

    try:
        # Explicitly use GET; this is a passive, non-destructive check.
        async with session.get(target_url, timeout=timeout, allow_redirects=True) as response:
            status = response.status
            if status != 200:
                return None

            # Read text body (ignore decode issues to keep scanning robust).
            body = await response.text(errors="ignore")
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return None

    lower_body = body.lower()
    matched = [kw for kw in keywords if kw.lower() in lower_body]
    if not matched:
        return None

    return AuditFinding(
        path=path,
        url=target_url,
        status=200,
        matched_keywords=matched,
        snippet=extract_snippet(body, matched[0]),
    )


async def audit_target(base_url: str, check_paths: Iterable[str]) -> list[AuditFinding]:
    """Run passive asynchronous checks for all candidate sensitive paths."""
    timeout = aiohttp.ClientTimeout(total=10, connect=5, sock_read=8)

    # No authentication headers/cookies are used; this stays passive.
    headers = {
        "User-Agent": "AutoSecAudit-PassiveConfigAudit/0.1",
        "Accept": "text/plain,text/html,*/*;q=0.8",
    }

    async with aiohttp.ClientSession(headers=headers) as session:
        tasks = [
            fetch_and_check(session=session, base_url=base_url, path=path, timeout=timeout)
            for path in check_paths
        ]
        results = await asyncio.gather(*tasks, return_exceptions=False)

    # Keep only confirmed findings.
    return [item for item in results if item is not None]


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Passive config exposure audit (GET-only, no login, no POST)."
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET_URL,
        help=f"Target base URL (default: {DEFAULT_TARGET_URL})",
    )
    parser.add_argument(
        "--paths",
        nargs="*",
        default=DEFAULT_CHECK_PATHS,
        help=f"Paths to check (default: {' '.join(DEFAULT_CHECK_PATHS)})",
    )
    return parser.parse_args()


async def async_main() -> None:
    """Entry point for async execution."""
    args = parse_args()
    findings = await audit_target(base_url=args.target, check_paths=args.paths)

    print("=== Passive Config Exposure Audit ===")
    print(f"Target: {args.target}")
    print(f"Checked paths: {args.paths}")
    print(f"Findings: {len(findings)}")

    if not findings:
        print("No sensitive exposure confirmed by current heuristic rules.")
        return

    for idx, finding in enumerate(findings, start=1):
        print(f"\n[{idx}] Potential Exposure")
        print(f"  URL: {finding.url}")
        print(f"  Path: {finding.path}")
        print(f"  Status: {finding.status}")
        print(f"  Matched keywords: {', '.join(finding.matched_keywords)}")
        print(f"  Snippet: {finding.snippet}")


def main() -> None:
    """Synchronous wrapper for asyncio runtime."""
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
