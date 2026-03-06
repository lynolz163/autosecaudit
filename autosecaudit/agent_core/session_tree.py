"""Session tree logging for multi-agent planning conversations."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any

from autosecaudit.core.models import utc_now_iso


@dataclass(frozen=True)
class SessionTreeNode:
    """One message/event node in the multi-agent conversation tree."""

    node_id: str
    parent_id: str | None
    role: str
    event_type: str
    content: str
    timestamp: str
    metadata: dict[str, Any]


class SessionTreeLogger:
    """Append-only in-memory session tree with periodic JSON persistence."""

    def __init__(self, output_path: Path | None = None) -> None:
        self._output_path = output_path
        self._nodes: list[SessionTreeNode] = []
        self._counter = 0

    def append(
        self,
        *,
        role: str,
        event_type: str,
        content: str,
        parent_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Append one node and return its stable node id."""
        self._counter += 1
        node_id = f"M{self._counter}"
        node = SessionTreeNode(
            node_id=node_id,
            parent_id=parent_id,
            role=str(role).strip() or "unknown",
            event_type=str(event_type).strip() or "message",
            content=str(content).strip(),
            timestamp=utc_now_iso(),
            metadata=dict(metadata or {}),
        )
        self._nodes.append(node)
        self.flush()
        return node_id

    def snapshot(self) -> list[dict[str, Any]]:
        """Return serializable tree nodes."""
        return [asdict(item) for item in self._nodes]

    def flush(self) -> None:
        """Persist tree to disk when output path is configured."""
        if self._output_path is None:
            return
        try:
            self._output_path.parent.mkdir(parents=True, exist_ok=True)
            self._output_path.write_text(
                json.dumps(self.snapshot(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except OSError:
            return

