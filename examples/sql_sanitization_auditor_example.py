"""Example usage of SQLSanitizationAuditor."""

from __future__ import annotations

from dataclasses import asdict
import json

from autosecaudit.auditors import SQLSanitizationAuditor


def main() -> None:
    auditor = SQLSanitizationAuditor(
        timeout_seconds=6.0,
        time_delay_seconds=5,
        time_delta_threshold_ms=3200,
    )

    result = auditor.audit_url(
        url="https://example.com/search",
        params={"q": "test"},
    )
    print(json.dumps(asdict(result), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
