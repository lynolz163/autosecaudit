"""Minimal parent-agent example: run AutoSecAudit in plan mode."""

from __future__ import annotations

import subprocess
from pathlib import Path


def main() -> None:
    workspace = Path.cwd()
    output_dir = workspace / "output" / "example-plan"
    output_dir.mkdir(parents=True, exist_ok=True)

    command = [
        "python",
        "-m",
        "autosecaudit",
        "--target",
        "example.com",
        "--mode",
        "plan",
        "--scope",
        "example.com",
        "--output",
        str(output_dir),
    ]
    subprocess.run(command, check=True, shell=False)
    print(output_dir / "agent" / "ActionPlan.json")


if __name__ == "__main__":
    main()
