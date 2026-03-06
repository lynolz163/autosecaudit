"""Example usage of XSSProtectionAuditor."""

from __future__ import annotations

from dataclasses import asdict
import json

from autosecaudit.auditors import XSSProtectionAuditor


def main() -> None:
    auditor = XSSProtectionAuditor(
        timeout_seconds=6.0,
        max_body_bytes=180_000,
    )

    result = auditor.audit_url(
        url="https://example.com/search",
        params={"q": "security"},
        verify_in_browser=False,
    )
    print(json.dumps(asdict(result), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
