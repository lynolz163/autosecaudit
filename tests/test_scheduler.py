from __future__ import annotations

from autosecaudit.agent_core.scheduler import Action, ActionScheduler


def _action(*, action_id: str, priority: int, cost: int) -> Action:
    return Action(
        action_id=action_id,
        tool_name=f"tool_{action_id}",
        target="https://example.com",
        options={},
        priority=priority,
        cost=cost,
        capabilities=["network_read"],
        idempotency_key=f"key-{action_id}",
        reason="test",
        preconditions=[],
        stop_conditions=[],
    )


def test_scheduler_allows_nonzero_priority_when_no_priority_zero_fits() -> None:
    scheduler = ActionScheduler(budget_remaining=9)
    scheduler.enqueue(_action(action_id="A1", priority=3, cost=4))
    scheduler.enqueue(_action(action_id="A2", priority=5, cost=6))

    selected = scheduler.pop_next()

    assert selected is not None
    assert selected.action_id == "A1"
    assert scheduler.budget_remaining == 5


def test_scheduler_prefers_priority_zero_when_low_budget_candidate_exists() -> None:
    scheduler = ActionScheduler(budget_remaining=9)
    scheduler.enqueue(_action(action_id="A1", priority=3, cost=4))
    scheduler.enqueue(_action(action_id="A2", priority=0, cost=5))

    selected = scheduler.pop_next()

    assert selected is not None
    assert selected.action_id == "A2"
    assert scheduler.budget_remaining == 4
