"""Logging setup and structured operation recorder."""

from __future__ import annotations

from dataclasses import asdict
import json
import logging
from pathlib import Path

from .models import OperationEvent


def configure_logging(log_dir: Path, level: int = logging.INFO) -> logging.Logger:
    """Configure and return the framework logger."""
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("autosecaudit")
    logger.setLevel(level)
    logger.propagate = False

    if logger.handlers:
        logger.handlers.clear()

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)

    file_handler = logging.FileHandler(log_dir / "autosecaudit.log", encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    return logger


class OperationRecorder:
    """Writes structured operation events to JSONL and standard logger."""

    def __init__(self, output_path: Path, logger: logging.Logger) -> None:
        self._output_path = output_path
        self._logger = logger
        self._output_path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: OperationEvent) -> None:
        """Persist one operation event to disk and emit a concise log line."""
        payload = asdict(event)
        try:
            with self._output_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(payload, ensure_ascii=False))
                stream.write("\n")
        except OSError as exc:
            self._logger.error("Failed to write operation event: %s", exc)

        self._logger.info(
            "[%s] %s | %s | %s",
            event.plugin_id,
            event.action,
            event.status,
            event.detail,
        )
