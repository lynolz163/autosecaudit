"""Minimal parent-agent example: run AutoSecAudit in agent mode."""

from __future__ import annotations

import subprocess
from pathlib import Path


def main() -> None:
    workspace = Path.cwd()
    output_dir = workspace / "output" / "example-agent"
    output_dir.mkdir(parents=True, exist_ok=True)
    agent_dir = output_dir / "agent"

    command = [
        "python",
        "-m",
        "autosecaudit",
        "--target",
        "https://example.com",
        "--mode",
        "agent",
        "--scope",
        "example.com",
        "--max-iterations",
        "4",
        "--global-timeout",
        "600",
        "--output",
        str(output_dir),
    ]
    if agent_dir.exists():
        command.extend(["--resume", str(agent_dir)])

    subprocess.run(command, check=True, shell=False)
    print(agent_dir / "agent_state.json")


if __name__ == "__main__":
    main()
