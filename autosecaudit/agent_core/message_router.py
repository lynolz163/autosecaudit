"""Lightweight message routing primitives for multi-agent coordination."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AgentMessage:
    """One routed message between agent roles."""

    sender: str
    receiver: str
    topic: str
    payload: dict[str, Any]


class MultiAgentMessageRouter:
    """In-memory router that records route history for observability."""

    def __init__(self) -> None:
        self._history: list[AgentMessage] = []

    def route(self, message: AgentMessage) -> AgentMessage:
        """Route one message and store in history."""
        self._history.append(message)
        return message

    def history(self) -> list[AgentMessage]:
        """Return routed history snapshot."""
        return list(self._history)

    def clear(self) -> None:
        """Clear routing history."""
        self._history.clear()

