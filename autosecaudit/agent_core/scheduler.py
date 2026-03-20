"""Deterministic priority scheduler for agent actions."""

from __future__ import annotations

from dataclasses import dataclass, field
import heapq
from typing import Any


@dataclass
class Action:
    """Executable action aligned with the planner schema."""

    action_id: str
    tool_name: str
    target: str
    options: dict[str, Any]
    priority: int
    cost: int
    capabilities: list[str]
    idempotency_key: str
    reason: str
    preconditions: list[str]
    stop_conditions: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Serialize action to plain dictionary."""
        return {
            "action_id": self.action_id,
            "tool_name": self.tool_name,
            "target": self.target,
            "options": self.options,
            "priority": self.priority,
            "cost": self.cost,
            "capabilities": self.capabilities,
            "idempotency_key": self.idempotency_key,
            "reason": self.reason,
            "preconditions": self.preconditions,
            "stop_conditions": self.stop_conditions,
        }


@dataclass(frozen=True)
class _QueueItem:
    """Internal heap item metadata."""

    priority: int
    insertion_index: int
    action_id: str


@dataclass
class ActionScheduler:
    """
    Deterministic action scheduler with budget control and deduplication.

    Rules:
    - Deduplicate by `idempotency_key`.
    - Pop by (priority, insertion_index, action_id).
    - Enforce budget and prefer priority-0 actions in low-budget mode.
    """

    budget_remaining: int
    low_budget_threshold: int = 10
    _heap: list[tuple[int, int, str]] = field(default_factory=list)
    _actions: dict[str, Action] = field(default_factory=dict)
    _scheduled_or_executed_keys: set[str] = field(default_factory=set)
    _insertion_counter: int = 0
    skipped_by_budget: list[dict[str, Any]] = field(default_factory=list)
    skipped_by_policy: list[dict[str, Any]] = field(default_factory=list)

    def enqueue(self, action: Action) -> bool:
        """
        Add one action into the queue.

        Returns:
            True if queued; False if skipped due to deduplication.
        """
        if action.idempotency_key in self._scheduled_or_executed_keys:
            self.skipped_by_policy.append(
                {
                    "action_id": action.action_id,
                    "tool_name": action.tool_name,
                    "target": action.target,
                    "reason": "duplicate_idempotency_key",
                }
            )
            return False

        self._scheduled_or_executed_keys.add(action.idempotency_key)
        self._actions[action.action_id] = action
        heapq.heappush(
            self._heap,
            (
                int(action.priority),
                self._insertion_counter,
                action.action_id,
            ),
        )
        self._insertion_counter += 1
        return True

    def has_next(self) -> bool:
        """Return whether queue still has candidates."""
        return bool(self._heap)

    def pop_next(self) -> Action | None:
        """
        Pop next action that satisfies remaining budget policy.

        Behavior:
        - If budget is low (< threshold), priority=0 actions are preferred.
        - If no priority=0 action can fit the remaining budget, allow the best-fitting queued action.
        - Actions that cannot fit the current budget are discarded and recorded.
        """
        while self._heap:
            _priority, _insertion_index, action_id = heapq.heappop(self._heap)
            action = self._actions.pop(action_id, None)
            if action is None:
                continue

            if (
                self.budget_remaining < self.low_budget_threshold
                and int(action.priority) != 0
                and self._has_selectable_priority_zero_action()
            ):
                self.skipped_by_budget.append(
                    {
                        "action_id": action.action_id,
                        "tool_name": action.tool_name,
                        "target": action.target,
                        "cost": action.cost,
                        "remaining_budget": self.budget_remaining,
                        "reason": "low_budget_priority_restriction",
                    }
                )
                continue

            if int(action.cost) > self.budget_remaining:
                self.skipped_by_budget.append(
                    {
                        "action_id": action.action_id,
                        "tool_name": action.tool_name,
                        "target": action.target,
                        "cost": action.cost,
                        "remaining_budget": self.budget_remaining,
                        "reason": "insufficient_budget",
                    }
                )
                continue

            self.budget_remaining -= int(action.cost)
            return action
        return None

    def _has_selectable_priority_zero_action(self) -> bool:
        """Return whether a priority-0 queued action can still run under the current budget."""
        return any(
            int(action.priority) == 0 and int(action.cost) <= self.budget_remaining
            for action in self._actions.values()
        )
