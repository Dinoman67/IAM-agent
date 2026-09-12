"""Structured agent decisions for Phase 2 autonomous reasoning."""

from __future__ import annotations

from typing import Any, Dict, Literal, Optional
from pydantic import BaseModel, Field

DecisionType = Literal["tool_call", "replan", "complete", "escalate", "abort"]


class AgentDecision(BaseModel):
    """Strongly-typed decision returned by Reasoner."""

    decision_type: DecisionType = Field(
        ...,
        description="Action category: 'tool_call', 'replan', 'complete', 'escalate', or 'abort'",
    )
    tool_name: Optional[str] = Field(
        default=None, description="Name of the tool to invoke when decision_type is 'tool_call'"
    )
    arguments: Dict[str, Any] = Field(
        default_factory=dict, description="Arguments for tool invocation"
    )
    reason: str = Field(
        default="", description="Explanatory justification and reasoning chain"
    )
    confidence: float = Field(
        default=1.0, ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0"
    )
    plan_update: Optional[Dict[str, Any]] = Field(
        default=None, description="Optional modifications to the active AgentPlan"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Arbitrary execution context metadata"
    )

    # Backward compatibility properties with Phase 1 Decision
    @property
    def action_type(self) -> Literal["call_tool", "complete", "fail"]:
        if self.decision_type == "tool_call":
            return "call_tool"
        if self.decision_type == "complete":
            return "complete"
        return "fail"

    @property
    def thought(self) -> str:
        return self.reason

    @property
    def tool_args(self) -> Dict[str, Any]:
        return self.arguments


class Decision(AgentDecision):
    """Alias/subclass of AgentDecision for strict backward-compatibility with Phase 1."""

    action_type_override: Optional[Literal["call_tool", "complete", "fail"]] = Field(
        default=None, alias="action_type"
    )
    tool_args_override: Optional[Dict[str, Any]] = Field(
        default=None, alias="tool_args"
    )
    thought_override: Optional[str] = Field(default=None, alias="thought")

    def __init__(self, **data: Any) -> None:
        # Handle Phase 1 parameter aliases
        if "action_type" in data and "decision_type" not in data:
            at = data["action_type"]
            if at == "call_tool":
                data["decision_type"] = "tool_call"
            elif at == "complete":
                data["decision_type"] = "complete"
            else:
                data["decision_type"] = "abort"
        if "tool_args" in data and "arguments" not in data:
            data["arguments"] = data["tool_args"]
        if "thought" in data and "reason" not in data:
            data["reason"] = data["thought"]
        super().__init__(**data)
