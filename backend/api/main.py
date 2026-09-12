"""FastAPI Application providing REST endpoints for the IAM Agent."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from backend.agent.controller import AgentController
from backend.agent.reasoner import DeterministicReasoner, LLMReasoner
from backend.environment.loader import load_environment
from backend.state.store import InMemoryStateStore
from backend.tools.iam_tools import create_default_tool_registry

app = FastAPI(
    title="Autonomous Cloud IAM Least-Privilege Mitigator API",
    description="Provider-agnostic autonomous IAM mitigation, simulation, and deterministic verification API",
    version="2.0.0",
)

# Global in-memory state store to persist runs across API calls
state_store = InMemoryStateStore()


class AgentRunRequest(BaseModel):
    goal: str = Field(
        default="Reduce excessive permissions for PaymentServiceRole without breaking required services.",
        description="Security mitigation goal",
    )
    role_id: str = Field(
        default="PaymentServiceRole",
        description="Target IAM role ID to mitigate",
    )
    use_mock: bool = Field(
        default=False,
        description="Force deterministic mock reasoner instead of LLM",
    )


class AgentRunResponse(BaseModel):
    run_id: str
    status: str
    goal: str
    role_id: Optional[str] = None
    current_plan: Optional[Dict[str, Any]] = None
    events: List[Dict[str, Any]] = Field(default_factory=list)
    final_result: Optional[Dict[str, Any]] = None
    verification_result: Optional[Dict[str, Any]] = None
    policy_diff: Optional[Dict[str, Any]] = None
    telemetry: Optional[Dict[str, Any]] = None


@app.get("/health")
def health_check() -> Dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok", "service": "iam-agent", "version": "2.0.0"}


@app.post("/api/agent/run", response_model=AgentRunResponse)
def run_agent(request: AgentRunRequest) -> AgentRunResponse:
    """Trigger an autonomous least-privilege mitigation run."""
    env = load_environment()
    tool_registry = create_default_tool_registry(env)

    # Determine reasoner engine
    if request.use_mock or os.getenv("MOCK_LLM", "false").lower() in ("true", "1", "yes"):
        reasoner = DeterministicReasoner(target_role_id=request.role_id)
    else:
        # LLMReasoner gracefully uses DeterministicReasoner fallback if no API key is provided
        reasoner = LLMReasoner(mock_fallback=True)

    controller = AgentController(
        reasoner=reasoner,
        tool_registry=tool_registry,
        state_store=state_store,
        environment=env,
    )

    state = controller.run(goal=request.goal, role_id=request.role_id)

    return AgentRunResponse(
        run_id=state.run_id,
        status=state.current_phase.lower(),
        goal=state.goal,
        role_id=state.current_role,
        current_plan=state.current_plan.model_dump() if state.current_plan else None,
        events=[event.model_dump() for event in state.audit_trail],
        final_result=state.final_outcome,
        verification_result=state.verification_result,
        policy_diff=state.policy_diff,
        telemetry=state.telemetry,
    )


@app.get("/api/agent/run/{run_id}", response_model=AgentRunResponse)
def get_run(run_id: str) -> AgentRunResponse:
    """Retrieve audit history, plan, and final outcome of an agent run."""
    state = state_store.get(run_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found.")

    return AgentRunResponse(
        run_id=state.run_id,
        status=state.current_phase.lower(),
        goal=state.goal,
        role_id=state.current_role,
        current_plan=state.current_plan.model_dump() if state.current_plan else None,
        events=[event.model_dump() for event in state.audit_trail],
        final_result=state.final_outcome,
        verification_result=state.verification_result,
        policy_diff=state.policy_diff,
        telemetry=state.telemetry,
    )
