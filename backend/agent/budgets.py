"""Bounded execution loop limits, budget tracking, and telemetry for IAM agent runs."""

from __future__ import annotations

import time
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class AgentBudget(BaseModel):
    """Hard configurable budget limits enforcing safe execution bounds."""

    max_iterations: int = Field(default=20, description="Max reasoning iterations")
    max_tool_calls: int = Field(default=30, description="Max deterministic tool invocations")
    max_replans: int = Field(default=5, description="Max dynamic plan revisions")
    max_runtime_seconds: float = Field(default=120.0, description="Max execution duration in seconds")
    max_context_events: int = Field(default=100, description="Max event window retained for reasoner")


class BudgetTracker:
    """Monitors live resource consumption against configured budget limits."""

    def __init__(self, budget: Optional[AgentBudget] = None) -> None:
        self.budget = budget or AgentBudget()
        self.iterations = 0
        self.tool_calls = 0
        self.replans = 0
        self.tokens_used: Optional[int] = None
        self.start_time: float = time.time()

    def record_iteration(self) -> None:
        self.iterations += 1

    def record_tool_call(self) -> None:
        self.tool_calls += 1

    def record_replan(self) -> None:
        self.replans += 1

    def record_tokens(self, count: int) -> None:
        if self.tokens_used is None:
            self.tokens_used = 0
        self.tokens_used += count

    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self.start_time

    def check_exhausted(self) -> Optional[str]:
        """Returns exhaustion reason if any budget limit is reached, else None."""
        if self.iterations >= self.budget.max_iterations:
            return f"MAX_ITERATIONS limit reached ({self.iterations}/{self.budget.max_iterations})"
        if self.tool_calls >= self.budget.max_tool_calls:
            return f"MAX_TOOL_CALLS limit reached ({self.tool_calls}/{self.budget.max_tool_calls})"
        if self.replans >= self.budget.max_replans:
            return f"MAX_REPLANS limit reached ({self.replans}/{self.budget.max_replans})"
        if self.elapsed_seconds >= self.budget.max_runtime_seconds:
            return f"MAX_RUNTIME_SECONDS exceeded ({self.elapsed_seconds:.1f}s/{self.budget.max_runtime_seconds}s)"
        return None

    def telemetry(self) -> Dict[str, Any]:
        """Returns auditable telemetry summary."""
        return {
            "iterations": f"{self.iterations}/{self.budget.max_iterations}",
            "tool_calls": f"{self.tool_calls}/{self.budget.max_tool_calls}",
            "replans": f"{self.replans}/{self.budget.max_replans}",
            "runtime_ms": int(self.elapsed_seconds * 1000),
            "tokens_used": self.tokens_used,
            "budget_limits": self.budget.model_dump(),
        }
