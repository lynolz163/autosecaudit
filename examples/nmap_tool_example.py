"""Example usage for NmapTool."""

from __future__ import annotations

import json

from autosecaudit.tools import NmapOutputFormat, NmapTool


def main() -> None:
    """
    Run a safe Nmap service scan and print structured JSON output.

    Requirements:
    - Nmap executable must be installed and available in PATH.
    - Target must be authorized for internal testing.
    """
    tool = NmapTool(
        nmap_path="nmap",
        timeout_seconds=90.0,
        output_format=NmapOutputFormat.XML,
    )

    result = tool.run(target="scanme.nmap.org", ports="22,80,443")
    if not result.ok:
        print(f"Scan failed: {result.error}")
        return

    print(json.dumps(result.data, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
